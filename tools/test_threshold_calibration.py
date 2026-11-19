import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from threshold_calibration import select_threshold, evaluate_scores


class ThresholdCalibrationTests(unittest.TestCase):
    def test_exact_budget_on_one_thousand_benign(self):
        y = [0]*1000 + [1]*200
        p = [i/1000 for i in range(1000)] + [0.98]*200
        t = select_threshold(y,p,0.0029)
        metrics = evaluate_scores(y,p,t)
        self.assertLessEqual(metrics['fpr'],0.0029)
        self.assertEqual(metrics['fp'],2)

    def test_ties_do_not_exceed_budget(self):
        y = [0]*1000 + [1]*100
        p = [0.1]*990 + [0.99]*10 + [0.99]*100
        t = select_threshold(y,p,0.0029)
        self.assertEqual(evaluate_scores(y,p,t)['fp'],0)

    def test_invalid(self):
        invalid = [([0,1],[0.1,float('nan')],0.0029),
                   ([1,1],[0.1,0.3],0.0029),
                   ([0,1],[0.1,0.2],-0.1),
                   ([0,2],[0.1,0.2],0.1)]
        for y,p,b in invalid:
            with self.subTest(y=y,p=p,b=b),self.assertRaises(ValueError):
                select_threshold(y,p,b)

    def test_stricter_threshold_never_increases_false_positives(self):
        y = [0]*1000 + [1]*100
        p = [i/1000 for i in range(1000)] + [.9]*100
        strict = select_threshold(y,p,.0029)
        loose = select_threshold(y,p,.01)
        self.assertGreaterEqual(strict,loose)

if __name__ == '__main__':
    unittest.main()
