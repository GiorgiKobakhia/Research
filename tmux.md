# Fuzzing tmux 

This report describes my work, which involved fuzzing tmux, finding a crash and analyzing why the input found by fuzzer caused such a result. I added a new fuzzer to existing OSS-Fuzz infrastructure. Let's go through each step I took during the process. 

## Setup 

### Clone oss-fuzz and tmux
```sh
git clone https://github.com/google/oss-fuzz.git
cd oss-fuzz/projects/tmux
git clone --depth 1 https://github.com/tmux/tmux.git
```
Now we can add new fuzzers and run them locally. 

### Add a new fuzzer

I added `format-fuzzer`, which targets the function `char *format_expand_time(struct format_tree *ft, const char *fmt)` in `format.c`. This target is easy to fuzz because it accepts a string input.

#### Fuzzing harness: `format-fuzzer.c`
```c
/* Minimal libFuzzer harness for tmux format expression parser. */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "tmux.h"

#define FORMAT_FUZZER_MAXLEN 1024

int
LLVMFuzzerTestOneInput(const u_char *data, size_t size)
{
    char *fmt;
    struct format_tree *ft;
    char *expanded;

    if (size == 0 || size > FORMAT_FUZZER_MAXLEN)
        return 0;

    /* Null-terminate the input safely. */
    fmt = malloc(size + 1);
    if (fmt == NULL)
        return 0;
    memcpy(fmt, data, size);
    fmt[size] = '\0';

    /* Create a minimal format tree with no client/item and expand. */
    ft = format_create(NULL, NULL, FORMAT_NONE, 0);
    if (ft == NULL) {
        free(fmt);
        return 0;
    }

    expanded = format_expand_time(ft, fmt);

    if (expanded != NULL)
        free(expanded);

    format_free(ft);
    free(fmt);
    return 0;
}

struct event_base *libevent;

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    const struct options_table_entry	*oe;

	global_environ = environ_create();
	global_options = options_create(NULL);
	global_s_options = options_create(NULL);
	global_w_options = options_create(NULL);
	for (oe = options_table; oe->name != NULL; oe++) {
		if (oe->scope & OPTIONS_TABLE_SERVER)
			options_default(global_options, oe);
		if (oe->scope & OPTIONS_TABLE_SESSION)
			options_default(global_s_options, oe);
		if (oe->scope & OPTIONS_TABLE_WINDOW)
			options_default(global_w_options, oe);
	}
	libevent = osdep_event_init();

	options_set_number(global_w_options, "monitor-bell", 0);
	options_set_number(global_w_options, "allow-rename", 1);
	options_set_number(global_options, "set-clipboard", 2);
	socket_path = xstrdup("dummy");

    return 0;
}
```

#### `format-fuzzer.dict`
```
"#{"
"}"
"#{session_name}"
"#{window_index}"
"#{pane_index}"
"#{host}"
"#{pane_title}"
"#{?"
"#{/}"
```

#### `format-fuzzer.options`
```
[libfuzzer]
max_len = 1024
```

### Makefile changes

Add the new fuzzer to the check programs section when fuzzing is enabled:

```
if NEED_FUZZING
#check_PROGRAMS = fuzz/input-fuzzer
#fuzz_input_fuzzer_LDFLAGS = $(FUZZING_LIBS)
#fuzz_input_fuzzer_LDADD = $(LDADD) $(tmux_OBJECTS)
check_PROGRAMS = fuzz/input-fuzzer fuzz/format-fuzzer
fuzz_input_fuzzer_LDFLAGS = $(FUZZING_LIBS)
fuzz_input_fuzzer_LDADD = $(LDADD) $(tmux_OBJECTS)
fuzz_format_fuzzer_LDFLAGS = $(FUZZING_LIBS)
fuzz_format_fuzzer_LDADD = $(LDADD) $(tmux_OBJECTS)
endif
```


### Dockerfile change
```sh
# RUN git clone --depth 1 https://github.com/tmux/tmux.git
COPY tmux/ $SRC/tmux
```

### `build.sh` (adjusted for fuzzing)
```sh
#!/bin/bash -eu
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# Ensure libevent can be found
export PKG_CONFIG_PATH="/usr/local/lib/"

./autogen.sh
./configure \
    --enable-fuzzing \
    FUZZING_LIBS="${LIB_FUZZING_ENGINE} -lc++" \
    LIBEVENT_LIBS="-Wl,-Bstatic -levent -Wl,-Bdynamic" \
    LIBTINFO_LIBS=" -l:libtinfo.a "

make -j"$(nproc)" check
find "${SRC}/tmux/fuzz/" -name '*-fuzzer' -exec cp -v '{}' "${OUT}"/ \;
find "${SRC}/tmux/fuzz/" -name '*-fuzzer.options' -exec cp -v '{}' "${OUT}"/ \;
find "${SRC}/tmux/fuzz/" -name '*-fuzzer.dict' -exec cp -v '{}' "${OUT}"/ \;

MAXLEN=$(grep -Po 'max_len\s+=\s+\K\d+' "${OUT}/input-fuzzer.options")

if [ ! -d "${WORK}/fuzzing_corpus" ]; then
    mkdir "${WORK}/fuzzing_corpus"
    cd "${WORK}/fuzzing_corpus"
    bash "${SRC}/tmux/tools/24-bit-color.sh" | \
        split -a4 -db$MAXLEN - 24-bit-color.out.
    perl "${SRC}/tmux/tools/256colors.pl" | \
        split -a4 -db$MAXLEN - 256colors.out.
    cat "${SRC}/tmux/tools/UTF-8-demo.txt" | \
        split -a4 -db$MAXLEN - UTF-8-demo.txt.
    cat "${SRC}/tmux-fuzzing-corpus/alacritty"/* | \
        split -a4 -db$MAXLEN - alacritty.
    cat "${SRC}/tmux-fuzzing-corpus/esctest"/* | \
        split -a4 -db$MAXLEN - esctest.
    cat "${SRC}/tmux-fuzzing-corpus/iterm2"/* | \
        split -a5 -db$MAXLEN - iterm2.
    zip -q -j -r "${OUT}/input-fuzzer_seed_corpus.zip" \
        "${WORK}/fuzzing_corpus/"

    # add fuzzing corpus for format-fuzzer
    zip -q -j -r "${OUT}/format-fuzzer_seed_corpus.zip" \
        "${WORK}/fuzzing_corpus/"

fi
```


## Fuzzing

I tried building fuzzer with different sanitizers. `address` sanitizer produced `heap-buffer-overflow` crash, while `coverage` sanitizer gave me a input that caused a timeout/hang. 

```sh
python3 infra/helper.py build_fuzzers --sanitizer=address tmux
```

```sh
python3 infra/helper.py build_fuzzers --sanitizer=coverage tmux
```

```sh
mkdir /tmp/corpus
python3 infra/helper.py run_fuzzer --corpus-dir=/tmp/corpus tmux format-fuzzer
```

I reduced the length of crashing inputs. Since the inputs contain unprintable characters, I will represent them as python bytes in the rest part of the report.

```sh
python3 -c 'import sys; print(repr(sys.stdin.buffer.read()))' < crash1
b'#'


python3 -c 'import sys; print(repr(sys.stdin.buffer.read()))' < crash2
b'#{w:\xee#{}}\n'
```

This input causes tmux to hang. It can be reproduced with:

```sh
tmux display-message "$(cat crash)"
```


## Investigation

I investigated the cause of the hang using `GDB`. Let's follow this long and boring path our input takes and see where it finally ends up. I will also mention where the `heap-buffer-overflow` happens.

We can see that `cmd_display_message_exec` calls `format_expand_time` and passes it the template, which corresponds to the argument provided to `display-message`. Subsequently, `format_expand_time` calls `format_expand1` to handle the expansion process.

```c
static enum cmd_retval
cmd_display_message_exec(struct cmd *self, struct cmdq_item *item)
{
...
    if (count != 0)
		template = args_string(args, 0);
	else
		template = args_get(args, 'F');

...
	if (args_has(args, 'l'))
		msg = xstrdup(template);
	else
		msg = format_expand_time(ft, template);

...
}
```

At this point, inside `format_expand1` the inner part of our second input - `b"w:\xee#{}"` - is passed to `format_replace` as a `fmt`. But before following that path, let's notice that if the first input - `b"#"` is passed to `format_expand1`, the variable `ch` reads outside the buffer. The investigation of the first input ends here, we can continue to follow the path of the second one.

```c
static char *
format_expand1(struct format_expand_state *es, const char *fmt)
{
...
	len = 64;
	buf = xmalloc(len);
	off = 0;

	while (*fmt != '\0') {
		if (*fmt != '#') {
			while (len - off < 2) {
				buf = xreallocarray(buf, 2, len);
				len *= 2;
			}
			buf[off++] = *fmt++;
			continue;
		}
		fmt++;

		ch = (u_char)*fmt++;
		switch (ch) {

...
		case '{':
			ptr = format_skip((char *)fmt - 2, "}");
			if (ptr == NULL)
				break;
			n = ptr - fmt;

			format_log(es, "found #{}: %.*s", (int)n, fmt);
			if (format_replace(es, fmt, n, &buf, &len, &off) != 0)
				break;
			fmt += n + 1;
			continue;
...
}
```

In `format_replace`, the input is first copied into the `copy` variable.

The input string is then split into parts. The first part, the `w` modifier, sets the `FORMAT_WIDTH` flag.
The remaining part of the input — `b"\xee#{}"` — is passed again to `format_expand1`, which removes the `#{}` portion. The resulting value, `b"\xee"`, is stored in `value`.

Finally, `value` is passed to `format_width`.

```c
static int
format_replace(struct format_expand_state *es, const char *key, size_t keylen,
    char **buf, size_t *len, size_t *off)
{
...
	/* Make a copy of the key. */
	copy = copy0 = xstrndup(key, keylen);
...
			case 'w':
				modifiers |= FORMAT_WIDTH;
				break;
...
		if (strstr(copy, "#{") != 0) {
			format_log(es, "expanding inner format '%s'", copy);
			value = format_expand1(es, copy);
		} 

...
    if (modifiers & FORMAT_WIDTH) {
		xasprintf(&new, "%u", format_width(value));
		free(value);
		value = new;
		format_log(es, "replacing with width: %s", new);
	}
...
}
```

We’ve reached the final stage of the pass, where the input becomes stuck in a while loop. Let’s examine why.

The byte `b"\xee"` is the beginning of a three-byte `UTF-8` character.
`format_width` calls `utf8_open`, which sets `ud->size` to `3`, appends `b"\xee"` to `ud->data`, and updates `ud->have` to `1`.
Next, `format_width` attempts to read the remaining two bytes of the `UTF-8` sequence, but no more bytes are available.

As a result, the while loop terminates, and `cp -= ud->have` is executed — moving `cp` back to point at `b"\xee"`.
On the next iteration, format_width tries to process the same incomplete UTF-8 sequence again, causing an infinite loop.

```c
u_int
format_width(const char *expanded)
{
...
	cp = expanded;
	while (*cp != '\0') {
		if (*cp == '#') {
...
		} else if ((more = utf8_open(&ud, *cp)) == UTF8_MORE) {
			while (*++cp != '\0' && more == UTF8_MORE)
				more = utf8_append(&ud, *cp);
			if (more == UTF8_DONE)
				width += ud.width;
			else
				cp -= ud.have;
        }
...
}
```

```c
enum utf8_state
utf8_open(struct utf8_data *ud, u_char ch)
{
	memset(ud, 0, sizeof *ud);
	if (ch >= 0xc2 && ch <= 0xdf)
		ud->size = 2;
	else if (ch >= 0xe0 && ch <= 0xef)
		ud->size = 3;
	else if (ch >= 0xf0 && ch <= 0xf4)
		ud->size = 4;
	else
		return (UTF8_ERROR);
	utf8_append(ud, ch);
	return (UTF8_MORE);
}

/* Append character to UTF-8, closing if finished. */
enum utf8_state
utf8_append(struct utf8_data *ud, u_char ch)
{
	int	width;

	if (ud->have >= ud->size)
		fatalx("UTF-8 character overflow");
	if (ud->size > sizeof ud->data)
		fatalx("UTF-8 character size too large");

	if (ud->have != 0 && (ch & 0xc0) != 0x80)
		ud->width = 0xff;

	ud->data[ud->have++] = ch;
	if (ud->have != ud->size)
		return (UTF8_MORE);

	if (!utf8_no_width) {
		if (ud->width == 0xff)
			return (UTF8_ERROR);
		if (utf8_width(ud, &width) != UTF8_DONE)
			return (UTF8_ERROR);
		ud->width = width;
	}

	return (UTF8_DONE);
}

```

## Summary

To sum up, in the first example, we saw that passing unexpected input causes read beyond the heap buffer. In the second example, the key observation is that the input gets expanded, and the `w` modifier triggers the `format_width` function with the argument `b"\xee"`, which is the only remaining part of the input. As a result, tmux enters an infinite loop, repeatedly attempting to process an invalid `UTF-8` character.
