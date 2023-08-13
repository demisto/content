import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json


def calculate_overall(data: dict = None) -> str:
    if not data:
        return ""
    results = [x['Result'] for x in data]
    if "Not Achieved" in results:
        return "Not Achieved"
    elif "Partially Achieved" in results:
        return "Partially Achieved"
    else:
        return "Achieved"


def main():

    query = "-status:closed -category:job type:\"NCSC CAF Assessment\""

    result_field = "cafbresultraw"
    answers_field = "cafbanswers"
    questions_field = "cafbquestions"
    assessment_field = "AssessmentB"

    incidents = demisto.executeCommand("getIncidents", {"query": query})[0]['Contents']['data']
    if len(incidents) < 1:
        return ""
    incidents = sorted(incidents, key=lambda x: x['id'])
    incident = incidents[0]
    original_question_data = json.loads(demisto.executeCommand("getList", {"listName": "NCSC CAF "
                                                                                       "Assessment"})[0]['Contents'])
    original_question_data = original_question_data[assessment_field]
    if incident:
        md: str = ""

        custom_fields = incident.get('CustomFields')
        assessment_questions = json.loads(custom_fields.get(questions_field))
        assessment_answers = json.loads(custom_fields.get(answers_field))
        assessment_details = json.loads(custom_fields.get(result_field))
        assessment_result = calculate_overall(assessment_details)
        answered_questions = str()
        for x in range(0, len(assessment_questions)):
            table = list()
            original_answers = [a.get('answers') for a in original_question_data if a['question']
                                == assessment_questions.get(str(x))][0]
            these_answers = assessment_answers.get(str(x))
            for answer in these_answers:
                verdict = [b['score'] for b in original_answers if b['answer'] == answer][0]
                verdict = "Achieved" if verdict == 2 else "Not Achieved" if verdict == 0 else "Partially Achieved"
                table.append(
                    {
                        "Answer": answer,
                        "Result": verdict
                    }
                )
                answers_markdown = tableToMarkdown(assessment_questions.get(str(x)), table, ['Answer', 'Result'])
            answered_questions += f"{answers_markdown}\n\n"

        md += f"### Provided answers\n\nBelow are the individual questions and responses provided for this " \
              f"objective:\n\n{answered_questions}\n\n"

        if assessment_result in ['Not Achieved', 'Partially Achieved']:
            md += "### Recommendations\n\nPlease review the following questions and their responses that result in " \
                  "an 'Achieved' outcome for this objective (the list only includes questions which have not " \
                  "resulted in 'Achieved'):\n\n"
            failed_questions = [x['Question'] for x in assessment_details if x['Result'] != "Achieved"]
            for question in original_question_data:
                if question.get('question') in failed_questions:
                    md += f"#### {question.get('question')}\n"
                    for answer in [x['answer'] for x in question['answers'] if x['score'] == 2]:
                        md += f"- {answer}\n"
                    md += "\n"

        else:
            md += "### Recommendations\n\nThere are no further recommendations to improve your result for this " \
                  "objectve. Good work!"

    else:
        md = ""
    demisto.results(md)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
