import json
import pprint

with open("/Users/kgal/partners/projects/SecurityScorecard/test_data/history_fact_score.json", "r") as f:
	d = json.load(f)


factor_scores = []
entries = d.get("entries")
for entry in entries:
	factors = entry.get("factors")
	for factor in factors:
		factor_score = {}
		factor_score["date"] = entry.get("date")
		factor_score["score"] = factor.get("score")
		factor_score["name"] = factor.get("name")
		# pprint.pprint(factor_score)
		factor_scores.append(factor_score)

pprint.pprint(factor_scores)