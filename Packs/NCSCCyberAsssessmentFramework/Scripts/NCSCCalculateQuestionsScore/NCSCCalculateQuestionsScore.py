import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

args = demisto.args()
assessment = args.get("assessment")
assessment_results = args.get("assessment_results")
original_data = json.loads(
    demisto.executeCommand("getList", {"listName": "NCSC CAF Assessment"})[0][
        "Contents"
    ]
).get(assessment)

questions = assessment_results.get("Questions")
answers = assessment_results.get("Answers")

assessment_output = list()
details_output = dict()
overall_achievement = None

for index, question in questions.items():
    question_result = None
    details = list()
    reason = list()

    current_question = [x for x in original_data if x["question"] == question][0]
    current_answers = current_question.get("answers")
    non_compliant_answers = [
        x["answer"] for x in current_question.get("answers") if x["score"] == 0
    ]
    compliant_answers = [
        x["answer"] for x in current_question.get("answers") if x["score"] == 2
    ]
    partially_compliant_answers = [
        x["answer"] for x in current_question.get("answers") if x["score"] == 1
    ]
    user_answers = answers[index]

    # Fill out the details
    for answer in user_answers:
        score = [x for x in current_answers if x["answer"] == answer][0].get("score")
        details.append(
            {
                "Answer": answer,
                "Status": "Achieved"
                if score == 2
                else "Partially achieved"
                if score == 1
                else "Not achieved",
            }
        )
    details_output[current_question.get("question")] = details

    # Check not achieved
    for answer in non_compliant_answers:
        if answer in user_answers:
            question_result = "Not Achieved"
            reason.append(answer)

    if question_result:
        assessment_output.append(
            {
                "Question": question,
                "Result": question_result,
                "Reason": ", ".join(reason),
            }
        )
        continue

    # Check fully achieved
    if not question_result:
        question_result = "Achieved"
        for answer in compliant_answers:
            if answer not in user_answers:
                question_result = None
                break

    if question_result:
        assessment_output.append(
            {
                "Question": question,
                "Result": question_result,
                "Reason": "The answers you provided are all in the 'Achieved' category",
            }
        )
        question_result = None
        continue

    # Check partial compliance
    if not question_result:
        question_result = "Partially Achieved"
        for answer in partially_compliant_answers:
            if answer not in user_answers:
                question_result = None
                break
        if question_result:
            assessment_output.append(
                {
                    "Question": question,
                    "Result": question_result,
                    "Reason": "All answers fall within 'Partially Achieved'",
                }
            )
            question_result = None
            continue

    # Finally, mark as partially acheived as there is not enough information
    assessment_output.append(
        {
            "Question": question,
            "Result": "Partially achieved with exceptions",
            "Reason": "The answers you provided fall in the 'Achieved' and 'Partially Achieved'.",
        }
    )

md = tableToMarkdown(
    f"Assessment results ({assessment}):",
    assessment_output,
    ["Question", "Result", "Reason"],
)

# Build the details
details_md = list()
for k, v in details_output.items():
    this_md = tableToMarkdown(k, v, ["Answer", "Status"])
    details_md.append(this_md)

# Ascertain the overall status of the assessment
if "Not Achieved" in [x["Result"] for x in assessment_output]:
    overall_achievement = {"Acheivement": "Not Achieved"}
elif False in [
    lambda x: True if x["Result"] == "Achieved" else False for x in assessment_output
]:
    overall_achievement = {"Achievement": "Partially Achieved"}
else:
    overall_achievement = {"Achievement": "Achieved"}

command_results = CommandResults(
    outputs_prefix=f"AssessmentResultsAchievement.{assessment}",
    outputs=overall_achievement,
    outputs_key_field="Achievement",
)
return_results(command_results)

command_results = CommandResults(
    outputs_prefix=f"AssessmentResults.{assessment}",
    outputs_key_field=["Question"],
    outputs=assessment_output,
    readable_output=md,
)
return_results(command_results)

command_results = CommandResults(
    outputs_prefix=f"AssessmentMarkdown.{assessment}", outputs=md, readable_output=md
)
return_results(command_results)

command_results = CommandResults(
    outputs_prefix=f"AssessmentResultsDetails.{assessment}",
    outputs="\n\n".join(details_md),
    readable_output="\n\n".join(details_md),
)
return_results(command_results)
