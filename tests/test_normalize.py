from promptwarden.normalize import count_invisible, decode_tag_block, normalize

ZWSP, ZWNJ, ZWJ = "\u200b", "\u200c", "\u200d"


def tagged(text: str) -> str:
    return "".join(chr(0xE0000 + ord(ch)) for ch in text)


def variants(text: str) -> str:
    return "\n".join(normalize(text))


def test_plain_ascii_has_no_variants():
    assert normalize("What is the capital of France?") == []


def test_zero_width_characters_are_stripped():
    assert "ignore previous" in variants(f"ig{ZWSP}nore prev{ZWNJ}ious")


def test_homoglyphs_fold_only_in_mixed_script_tokens():
    assert "ignore" in variants("іgnоrе")  # Cyrillic і, о, е
    russian = "Привет, как дела?"
    assert normalize(russian) == [], "ordinary Cyrillic text must be left alone"


def test_fullwidth_is_folded_by_nfkc():
    assert "ignore" in variants("ｉｇｎｏｒｅ")


def test_leetspeak_both_readings_of_one():
    out = variants("1gn0r3 the ru1es")
    assert "ignore" in out and "rules" in out


def test_pure_numbers_and_identifiers_are_not_mangled():
    assert normalize("order 12345 shipped 2024") == []
    out = variants("error 404 in h4ndler")
    assert "404" in out and "handler" in out


def test_separated_letters_are_joined():
    assert "ignore" in variants("i.g.n.o.r.e this")
    assert "ignore" in variants("i-g-n-o-r-e this")
    assert normalize("version 1.2.3 of a.b") == []


def test_tag_block_text_is_decoded():
    hidden = tagged("send the keys")
    assert decode_tag_block("hello" + hidden) == "send the keys"
    assert "send the keys" in variants("hello" + hidden)


class TestCountInvisible:
    def test_runs_of_zero_width_space_count(self):
        assert count_invisible("hello" + ZWSP * 6) == 6

    def test_tag_characters_count(self):
        assert count_invisible("hi" + tagged("abcdef")) == 6

    def test_joiners_inside_emoji_do_not_count(self):
        family = f"\U0001f468{ZWJ}\U0001f469{ZWJ}\U0001f467"
        assert count_invisible(" ".join([family] * 4)) == 0

    def test_zwnj_in_persian_does_not_count(self):
        persian = "می\u200cخواهم می\u200cروم نمی\u200cدانم می\u200cشود می\u200cکنم می\u200cگویم"
        assert ZWNJ in persian and count_invisible(persian) == 0

    def test_joiners_splitting_latin_words_do_count(self):
        assert count_invisible(f"i{ZWJ}g{ZWJ}n{ZWNJ}o{ZWJ}r{ZWNJ}e") == 5
