import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos.office import pack_ml as ml  # noqa: E402
from kos.office.ui import FakeHost, run  # noqa: E402

XOR = [[0, 0], [0, 1], [1, 0], [1, 1]]
XOR_Y = [0, 1, 1, 0]


class TestParse(unittest.TestCase):
    def test_header_and_rows(self):
        h, rows = ml.parse("a,b,y\n1,2,3\n4 ,5,6\n# c\n")
        self.assertEqual(h, ["a", "b", "y"])
        self.assertEqual(rows, [[1, 2, 3], [4, 5, 6]])

    def test_refusals(self):
        for bad in ["", "1,2\n3", "1,2\n3,x", "1,2\n3,nan", "1,2\n3,inf", "1\n2", "a,b\n1,2\x00\n3,4",
                    "\n".join("1,2" for _ in range(600)), "1," * 20 + "1\n" + "1," * 20 + "1",
                    "x" * 30000, "1,2", "1,2\n3,1e99"]:
            with self.assertRaises(ml.MLError, msg=bad[:20]):
                ml.parse(bad)
        with self.assertRaises(ml.MLError):
            ml.parse(None)


class TestAlgorithms(unittest.TestCase):
    def test_linreg_exact(self):
        X = [[x] for x in range(1, 9)]
        y = [2 * x[0] + 1 for x in X]
        m, _ = ml.train("linreg", X, y, std=False)
        self.assertAlmostEqual(m["coef"][0], 1, 8)
        self.assertAlmostEqual(m["coef"][1], 2, 8)
        m2, _ = ml.train("linreg", X, y)            # standardised: predictions still exact
        self.assertAlmostEqual(ml.predict(m2, [[10]])[0], 21, 8)
        r = ml.metrics_reg(y, ml.predict(m2, X))
        self.assertAlmostEqual(r["rmse"], 0, 8)
        self.assertAlmostEqual(r["r2"], 1, 8)

    def test_linreg_two_features_and_collinear(self):
        X = [[1, 0], [0, 1], [1, 1], [2, 1], [3, 5]]
        y = [3 * a - 2 * b + 4 for a, b in X]
        m, _ = ml.train("linreg", X, y, std=False)
        for got, want in zip(m["coef"], [4, 3, -2]):
            self.assertAlmostEqual(got, want, 7)
        with self.assertRaises(ml.MLError):
            ml.train("linreg", [[1, 2], [2, 4], [3, 6], [4, 8]], [1, 2, 3, 4], std=False)

    def test_metrics_exact(self):
        m = ml.metrics_cls([0, 0, 1, 1, 1], [0, 1, 1, 1, 0], [0, 1])
        self.assertEqual(m["confusion"], [[1, 1], [1, 2]])
        self.assertAlmostEqual(m["accuracy"], 0.6)
        pr, rc, f = m["per_class"][1]
        self.assertAlmostEqual(pr, 2 / 3)
        self.assertAlmostEqual(rc, 2 / 3)
        self.assertAlmostEqual(f, 2 / 3)
        r = ml.metrics_reg([1, 2, 3], [1, 2, 4])
        self.assertAlmostEqual(r["rmse"], (1 / 3) ** 0.5)
        self.assertAlmostEqual(r["r2"], 1 - 1 / 2)

    def test_kmeans_blobs(self):
        A = [[0, 0], [1, 0], [0, 1], [1, 1]]
        B = [[10, 10], [11, 10], [10, 11], [11, 11]]
        C = [[0, 10], [1, 10], [0, 11], [1, 11]]
        cen, lab, hist = ml.kmeans(A + B + C, 3, 7)
        self.assertEqual(len(set(lab[0:4])), 1)
        self.assertEqual(len(set(lab[4:8])), 1)
        self.assertEqual(len(set(lab[8:12])), 1)
        self.assertEqual(len({lab[0], lab[4], lab[8]}), 3)
        self.assertEqual(sorted(tuple(c) for c in cen), [(0.5, 0.5), (0.5, 10.5), (10.5, 10.5)])
        self.assertAlmostEqual(hist[-1], 12 * 0.5)
        self.assertLessEqual(hist[-1], hist[0])

    def test_tree_separable(self):
        X = [[1, 5], [2, 4], [3, 9], [7, 1], [8, 7], [9, 2]]
        y = [0, 0, 0, 1, 1, 1]
        m, _ = ml.train("tree", X, y, 3, std=False)
        self.assertEqual(m["tree"]["f"], 0)
        self.assertEqual(m["tree"]["t"], 5.0)
        self.assertEqual(ml.predict(m, X), [0, 0, 0, 1, 1, 1])
        self.assertEqual(ml.predict(m, [[4.9, 0], [5.1, 0]]), [0, 1])

    def test_tree_depth_cap_and_greedy_xor(self):
        X = [[1], [2], [5], [6], [9], [10]]
        y = [0, 0, 1, 1, 0, 0]                      # a band: needs two splits
        m1, _ = ml.train("tree", X, y, 1, std=False)
        self.assertLess(ml.metrics_cls(y, ml.predict(m1, X), [0, 1])["accuracy"], 1)
        m2, _ = ml.train("tree", X, y, 2, std=False)
        self.assertEqual(ml.predict(m2, X), y)
        mx, _ = ml.train("tree", XOR, XOR_Y, 4)      # greedy gini finds no first split on XOR: one leaf
        self.assertIn("c", mx["tree"])

    def test_knn_and_nb_and_logistic(self):
        X = [[0, 0], [1, 0], [0, 1], [10, 10], [11, 10], [10, 11]]
        y = [0, 0, 0, 1, 1, 1]
        for algo in ("knn", "nb", "logistic"):
            m, loss = ml.train(algo, X, y, 3 if algo == "knn" else None)
            self.assertEqual(ml.predict(m, X), y, algo)
            self.assertEqual(ml.predict(m, [[0.5, 0.5], [9, 9]]), [0, 1], algo)
        self.assertLess(loss[-1], loss[0])
        self.assertAlmostEqual(loss[0], 0.693147, 5)
        with self.assertRaises(ml.MLError):
            ml.train("logistic", X, [0, 1, 2, 0, 1, 2])

    def test_perceptron_xor(self):
        m, loss = ml.train("mlp", XOR, XOR_Y, 1500, seed=1)
        self.assertEqual(ml.predict(m, XOR), XOR_Y)
        self.assertLess(loss[-1], loss[0])

    def test_determinism(self):
        a, la = ml.train("mlp", XOR, XOR_Y, 200, seed=5)
        b, lb = ml.train("mlp", XOR, XOR_Y, 200, seed=5)
        self.assertEqual(la, lb)
        self.assertEqual(ml.export(a), ml.export(b))
        c, _ = ml.train("mlp", XOR, XOR_Y, 200, seed=6)
        self.assertNotEqual(ml.export(a), ml.export(c))
        rows = [[i, i % 3] for i in range(20)]
        self.assertEqual(ml.split(rows, 25, 3), ml.split(rows, 25, 3))
        self.assertEqual(len(ml.split(rows, 25, 3)[1]), 5)

    def test_caps(self):
        big = [[float(i), float(i % 7)] for i in range(500)]
        with self.assertRaises(ml.MLError):
            ml.train("mlp", big, [i % 2 for i in range(500)], 3000)
        with self.assertRaises(ml.MLError):
            ml.train("logistic", [[i % 5, 1.0 * i, i % 3, i % 11, i % 13, i % 17, i % 19, i % 23, i % 29, i % 31, i % 37] for i in range(500)],
                     [i % 2 for i in range(500)], 2000)
        with self.assertRaises(ml.MLError):
            ml.train("tree", [[i] for i in range(30)], list(range(30)))       # 30 classes
        with self.assertRaises(ml.MLError):
            ml.train("tree", [[1], [2]], [1, 1])
        with self.assertRaises(ml.MLError):
            ml.predict(ml.train("nb", [[0], [1]], [0, 1])[0], [[1, 2]])

    def test_export_json_and_curve(self):
        m, loss = ml.train("logistic", [[0], [1], [2], [3]], [0, 0, 1, 1], 50)
        d = json.loads(ml.export(m))
        self.assertEqual(d["algo"], "logistic")
        self.assertEqual(len(ml.curve(loss, rows=10)), 11)
        self.assertEqual(len(ml.curve([])), 1)


class TestScreen(unittest.TestCase):
    def test_flow_draws_and_saves(self):
        keys = ["down", "down", "down", "down", "down", "down", "down", "enter", "escape",   # train (fails? shows report)
                "up", "enter", "escape"]
        h = FakeHost(keys)
        lab = ml.ENTRIES[0].args["make"](h, ml.ENTRIES[0])
        run(h, lab)
        self.assertTrue(h.frames)
        self.assertIn("Machine Learning Lab", h.frames[0][0])

    def test_train_export_and_predict_paths(self):
        h = FakeHost()
        lab = ml.Lab(h)
        self.assertEqual(lab.run_train()[1].title, "Report")
        text = "\n".join(lab.run_train()[1].lines)
        self.assertIn("accuracy 1.0000", text)
        self.assertEqual(lab.show_curve()[1].title, "Loss curve")
        self.assertEqual(lab.show_export()[0], "push")
        self.assertEqual(json.loads(h.data["ml_model"])["algo"], "mlp")
        lab.ask_row()[1].on_done("1 0")
        self.assertEqual(lab.ask_row()[1].on_done("1 0")[1].lines, ["prediction: 1"])
        self.assertEqual(lab.ask_row()[1].on_done("oops")[1].title, "Bad row")
        lab.data = "a,b\n1,x\n2,3"
        self.assertEqual(lab.run_train()[1].title, "Cannot train")
        lab.save()
        self.assertIn("ml_state", h.data)
        self.assertEqual(ml.Lab(h).data, "a,b\n1,x\n2,3")

    def test_every_algo_on_every_sample(self):
        h = FakeHost()
        lab = ml.Lab(h)
        for _, data, test in ml.SAMPLES:
            lab.data, lab.test = data, test
            for a in ml.ALGOS:
                lab.algo = a
                r = lab.run_train()
                self.assertIn(r[1].title, ("Report", "Cannot train"), a)
                if a == "kmeans":
                    self.assertEqual(r[1].title, "Report")

    def test_hostile_keys(self):
        h = FakeHost(["enter", "x", "ctrl-u", "backspace", "escape", "down", "enter", "5", "enter", "\x01", "pagedown", "end", "escape"] * 3)
        run(h, ml.Lab(h))


if __name__ == "__main__":
    unittest.main()
