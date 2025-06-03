import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from ollama import chat, ChatResponse
import json
from typing import List, Dict


def analyze_incident(incident_id: str, text: str, context_data: Dict, model: str) -> str:
    """
    Analyzes an incident using Ollama LLM with additional context data.

    Args:
        incident_id (str): The ID of the incident.
        text (str): The incident description.
        context_data (Dict): The extracted context data.
        model (str): The name of the model to use.

    Returns:
        str: The AI-generated analysis.
    """
    # Convert context data into a readable format
    context_summary = json.dumps(context_data, indent=2) if context_data else "No additional context available."

    messages: List[Dict[str, str]] = [
        {"role": "system", "content": "You are an AI assistant trained to analyze security incidents using contextual data."},
        {"role": "user", "content": f"Incident ID: {incident_id}\n\nDescription: {text}\n\nContext Data: {context_summary}\n\nAnalyze this incident and provide a detailed assessment."}
    ]

    try:
        response: ChatResponse = chat(model=model, messages=messages)
        return response.message.content
    except Exception as e:
        raise DemistoException(f"Error in incident analysis: {str(e)}")


def main() -> None:
    """
    Main function to retrieve context data, analyze the incident, and return results.
    """
    try:
        # Get incident ID
        incident_id = demisto.incident().get('id')
        text = demisto.args().get('text', '')
        model = demisto.args().get('model', '')

        # Retrieve incident context data
        context_data = demisto.context()

        if not text:
            raise DemistoException("Incident text is required")

        # Analyze the incident with context data
        result = analyze_incident(incident_id, text, context_data, model)

        # Generate output
        readable_output = tableToMarkdown(
            f"Incident Analysis Result for ID: {incident_id}",
            {"Analysis": result}
        )

        return_results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'HumanReadable': readable_output
        })

    except Exception as e:
        return_error(f"Error in Incident Analysis: {str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
