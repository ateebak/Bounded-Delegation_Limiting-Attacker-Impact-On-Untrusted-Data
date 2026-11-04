"""Unit tests for the DRIFT native-call shim (D-037, extended D-049): MiniMax's native tool-call syntaxes are rewritten
into DRIFT's `<function_call>[fn(k=v)]</function_call>` format (examples from stage 10 run 20261030T101842Z-5195df)."""
import re, sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "experiments/harness"), str(ROOT / "experiments/costs")]
import baselines as B


def calls(text):
    m = re.search(r"<function_call>(.*?)</function_call>", B.native_to_drift(text), re.S)  # DRIFT reads the first block
    return m.group(1).strip() if m else None


def test_json_tool_calls():
    t = '<tool_call>\n<tool_call>\n{"name": "read_file", "arguments": {"file_path": "bill.txt"}}\n</tool_call>\n' \
        '<tool_call>\n{"name": "get_iban", "arguments": {}}\n</tool_call>'
    assert calls(t) == "[read_file(file_path='bill.txt'), get_iban()]"


def test_json_list_and_adjacent_objects():
    t = '<tool_call>\n[{"name": "browse_webpage", "arguments": {"url": "www.a.com"}}, {"name": "f", "arguments": {"n": 2}}]\n</tool_call>'
    assert calls(t) == "[browse_webpage(url='www.a.com'), f(n=2)]"


def test_invoke_xml_with_stray_token():
    t = '<function_thought>x</function_thought>\n<tool_call>\n]<]minimax[>[<invoke name="get_most_recent_transactions">' \
        ']<]minimax[>[<n>5]<]minimax[>[</n>]<]minimax[>[</invoke>\n]<]minimax[>[<invoke name="get_scheduled_transactions">' \
        ']<]minimax[>[</invoke>\n</tool_call>'
    assert calls(t) == "[get_most_recent_transactions(n=5), get_scheduled_transactions()]"


def test_invoke_parameter_tags():
    t = '-fn_call>\n<invoke name="get_day_calendar_events">\n<parameter name="day">2024-05-15</parameter>\n</invoke>'
    assert calls(t) == "[get_day_calendar_events(day='2024-05-15')]"


def test_drift_list_under_native_tag_replaces_empty_block():
    t = '<function_call>[]</function_call>\n<tool_call>\n  [browse_webpage(url="www.bookclub.com"), read_file(path="/x")]\n</tool_call>'
    assert calls(t) == '[browse_webpage(url="www.bookclub.com"), read_file(path="/x")]'


def test_null_becomes_none():
    assert calls('<tool_call>\n[search(query="k", date=null)]\n') == '[search(query="k", date=None)]'


def test_valid_drift_call_kept_and_token_stripped():
    t = '<function_call>[read_file(path="/a")]</function_call>]<]minimax[>[<tool_call><invoke name="read_file"><path>/a</path></invoke></tool_call>'
    out = B.native_to_drift(t)
    assert "minimax" not in out and calls(t) == '[read_file(path="/a")]' and out.count("<function_call>") == 1


def test_plain_answer_unchanged():
    t = "<function_thought>done</function_thought>\n<final_answer>Paid [see list] (ok)</final_answer>"
    assert B.native_to_drift(t) == t


def test_gemma_native_still_translated():
    assert calls('<|tool_call>call:get_iban{}<tool_call|>') == "[get_iban()]"
