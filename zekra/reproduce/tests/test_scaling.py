"""Small semantic checks for the research adapter; no Docker or proof execution."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("scaling_runner", Path(__file__).resolve().parents[1] / "scaling/run_scaling.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class AdapterTests(unittest.TestCase):
    def test_static_returns_follow_continuation_without_entering_nested_callee(self):
        nodes = [1,2,3,4,5,6]
        typed = {(1,"cal",2),(1,"crt",1),(2,"cal",3),(2,"crt",5),
                 (2,"jmp",6),(3,"jmp",4),(5,"jmp",2)}
        self.assertEqual(runner.static_return_edges(nodes,typed),{(4,5),(6,1)})

    def test_declared_conditional_return_is_statically_checked(self):
        typed = {(1,"cal",2),(1,"crt",1),(2,"cal",3),(2,"crt",5),
                 (3,"jmp",4),(5,"jmp",2)}
        self.assertEqual(runner.static_return_edges([1,2,3,4,5],typed,{(4,5),(2,1)}),{(4,5),(2,1)})
        with self.assertRaisesRegex(ValueError,"unreachable"):
            runner.static_return_edges([1,2,3,4,5,7],typed,{(4,5),(2,1),(7,1)})

    def test_return_must_match_stack_and_static_return_relation(self):
        typed = {(1,"cal",2),(1,"crt",1)}
        good = [("call",2,1),("ret",1,None)]
        runner.audit(1,1,good,[1,2],typed,{(2,1)})
        with self.assertRaisesRegex(ValueError,"invalid return"):
            runner.audit(1,1,good,[1,2],typed,set())
        with self.assertRaisesRegex(ValueError,"invalid return"):
            runner.audit(1,1,[("ret",1,None)],[1,2],typed,{(1,1)})

    def test_repository_compressor_preserves_balanced_repetition(self):
        period = [("call",3,5),("jump",4,None),("ret",5,None),("jump",2,None)]
        original = [("call",2,1)] + period*3 + [("ret",1,None)]
        projected, decisions = runner.load_compressor()(original)
        self.assertEqual(projected,[("call",2,1)]+period+[("ret",1,None)])
        self.assertEqual(decisions,[{"sequence_length":4,"repetitions":3}])

    def test_dummy_address_is_not_an_ordinary_node(self):
        with self.assertRaises(ValueError): runner.addr("0x0")
        with self.assertRaises(ValueError): runner.addr("0x1000000")
        self.assertEqual(runner.addr("0x400000"),0x400000)

    def test_level_budget_checked_on_full_static_graph(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder)/"source"; source.mkdir()
            nodes = list(range(1,26))
            (source/"translator").write_text("\n".join(hex(n) for n in nodes)+"\n")
            # The unused node has neighbors spanning three distinct buckets.
            (source/"typed_cfg").write_text("0x1 cal 0x2\n0x1 crt 0x1\n0x19 jmp 0x1\n0x19 jmp 0x9\n0x19 jmp 0x11\n")
            (source/"recorded_path").write_text("initial_node=0x1 final_node=0x1\ncall 0x2 0x1\nret 0x1\n")
            with self.assertRaisesRegex(ValueError,"requires 3 adjacency levels"):
                runner.prepare_inputs(source,Path(folder)/"prepared",2)


if __name__ == "__main__": unittest.main()
