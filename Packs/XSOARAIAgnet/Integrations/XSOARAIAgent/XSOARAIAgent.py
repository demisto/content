import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import os
import warnings
import contextlib
import requests
from urllib3.exceptions import InsecureRequestWarning
import httpx
from langchain_openai import ChatOpenAI
from langchain.agents import (
    create_openai_functions_agent,
    Tool,
    AgentExecutor,
)
from langchain.prompts import PromptTemplate
from langchain import hub
from langchain_neo4j import (
    Neo4jGraph,
    GraphCypherQAChain,
)

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """
# HTTPX_CLIENT = httpx.Client(verify=False)
NEO4J_URI = ""
NEO4J_USERNAME = ""
NEO4J_PASSWORD = ""
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
TOOLS = [
    Tool(
        name="Graph",
        func=content_cypher_chain.invoke,
        description="""Useful for requests to run integration commands or scripts. 
        Use the entire prompt as input to the tool. 
        For instance, if the prompt is "Provide details about incident ID 23 in ServiceNow?",
        the input should be "Provide details about incident ID 23 in ServiceNow?".
        """,
    ),
    Tool(
        name="Question",
        func=content_questoin_chain.invoke,
        description="""Useful for answering questions about integrations,
        scripts, incident types, incident fields, layouts, classifiers, mappers.
        Use the entire prompt as input to the tool. For instance, 
        if the prompt is "How to configure the Virus Total integration?", 
        the input should be "How to configure the Virus Total integration?".
        """,
    ),
]
CYPHER_GENERATION_TEMPLATE = """
Task:
Generate Cypher query for a Neo4j graph database.

Instructions:
Use only the provided relationship types and properties in the schema.
Do not use any other relationship types or properties that are not provided.

Schema:
{schema}

Note:
Do not include any explanations or apologies in your responses.
Do not respond to any questions that might ask anything other than
for you to construct a Cypher statement. Do not include any text except
the generated Cypher statement. Make sure the direction of the relationship is
correct in your queries. Make sure you alias both entities and relationships
properly. Do not run any queries that would add to or delete from
the database. Make sure to alias all statements that follow as with
statement (e.g. WITH v as visit, c.billing_amount as billing_amount)
If you need to divide numbers, make sure to
filter the denominator to be non zero.

Examples:
# Who is the oldest patient and how old are they?
MATCH (p:Patient)
RETURN p.name AS oldest_patient,
       duration.between(date(p.dob), date()).years AS age
ORDER BY age DESC
LIMIT 1

# Which physician has billed the least to Cigna
MATCH (p:Payer)<-[c:COVERED_BY]-(v:Visit)-[t:TREATS]-(phy:Physician)
WHERE p.name = 'Cigna'
RETURN phy.name AS physician_name, SUM(c.billing_amount) AS total_billed
ORDER BY total_billed
LIMIT 1

# Which state had the largest percent increase in Cigna visits
# from 2022 to 2023?
MATCH (h:Hospital)<-[:AT]-(v:Visit)-[:COVERED_BY]->(p:Payer)
WHERE p.name = 'Cigna' AND v.admission_date >= '2022-01-01' AND
v.admission_date < '2024-01-01'
WITH h.state_name AS state, COUNT(v) AS visit_count,
     SUM(CASE WHEN v.admission_date >= '2022-01-01' AND
     v.admission_date < '2023-01-01' THEN 1 ELSE 0 END) AS count_2022,
     SUM(CASE WHEN v.admission_date >= '2023-01-01' AND
     v.admission_date < '2024-01-01' THEN 1 ELSE 0 END) AS count_2023
WITH state, visit_count, count_2022, count_2023,
     (toFloat(count_2023) - toFloat(count_2022)) / toFloat(count_2022) * 100
     AS percent_increase
RETURN state, percent_increase
ORDER BY percent_increase DESC
LIMIT 1

# How many non-emergency patients in North Carolina have written reviews?
MATCH (r:Review)<-[:WRITES]-(v:Visit)-[:AT]->(h:Hospital)
WHERE h.state_name = 'NC' and v.admission_type <> 'Emergency'
RETURN count(*)

String category values:
Test results are one of: 'Inconclusive', 'Normal', 'Abnormal'
Visit statuses are one of: 'OPEN', 'DISCHARGED'
Admission Types are one of: 'Elective', 'Emergency', 'Urgent'
Payer names are one of: 'Cigna', 'Blue Cross', 'UnitedHealthcare', 'Medicare',
'Aetna'

A visit is considered open if its status is 'OPEN' and the discharge date is
missing.
Use abbreviations when
filtering on hospital states (e.g. "Texas" is "TX",
"Colorado" is "CO", "North Carolina" is "NC",
"Florida" is "FL", "Georgia" is "GA", etc.)

Make sure to use IS NULL or IS NOT NULL when analyzing missing properties.
Never return embedding properties in your queries. You must never include the
statement "GROUP BY" in your query. Make sure to alias all statements that
follow as with statement (e.g. WITH v as visit, c.billing_amount as
billing_amount)
If you need to divide numbers, make sure to filter the denominator to be non
zero.

The question is:
{question}
"""
QA_GENERATION_TEMPLATE = """You are an assistant that takes the results
from a Neo4j Cypher query and forms a human-readable response. The
query results section contains the results of a Cypher query that was
generated based on a user's natural language question. The provided
information is authoritative, you must never doubt it or try to use
your internal knowledge to correct it. Make the answer sound like a
response to the question.

Query Results:
{context}

Question:
{question}

If the provided information is empty, say you don't know the answer.
Empty information looks like this: []

If the information is not empty, you must provide an answer using the
results. If the question involves a time duration, assume the query
results are in units of days unless otherwise specified.

When names are provided in the query results, such as hospital names,
beware of any names that have commas or other punctuation in them.
For instance, 'Jones, Brown and Murray' is a single hospital name,
not multiple hospitals. Make sure you return any list of names in
a way that isn't ambiguous and allows someone to tell what the full
names are.

Never say you don't have the right information if there is data in
the query results. Always use the data in the query results.

Helpful Answer:
"""

""" CLIENT CLASS """


class Agent:
    """
    """

    def __init__(self, model, api_key):
        self.model = model
        self.api_key = api_key

    def generate_cypher_chain(self, graph: Neo4jGraph):
        cypher_generation_prompt = PromptTemplate(
            input_variables=["schema", "question"], template=CYPHER_GENERATION_TEMPLATE
        )
        qa_generation_prompt = PromptTemplate(
            input_variables=["context", "question"], template=QA_GENERATION_TEMPLATE
        )

        cypher_chain = GraphCypherQAChain.from_llm(
            cypher_llm=ChatOpenAI(model=self.model, temperature=0),
            qa_llm=ChatOpenAI(model=self.model, temperature=0),
            graph=graph,
            verbose=True,
            qa_prompt=qa_generation_prompt,
            cypher_prompt=cypher_generation_prompt,
            validate_cypher=True,
            top_k=100,
            allow_dangerous_requests=True,
        )

        return cypher_chain

    def test(self):
        ...

    def execute(self, query: str):
        demisto.debug(f'Executing {query} with model {self.model}')
        return ""


""" HELPER FUNCTIONS """


def connect_to_graph():
    graph = Neo4jGraph(
        url=NEO4J_URI,
        username=NEO4J_USERNAME,
        password=NEO4J_PASSWORD,
    )

    graph.refresh_schema()

    return graph


""" COMMAND FUNCTIONS """


def test_module(agent: Agent) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises:
     exceptions if something goes wrong.

    Args:
        Client: client to use

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    agent.test()  # No errors, the api is working
    return "ok"


def xsoar_ai_agent_execute_command(agent: Agent, args: dict[str, Any]) -> CommandResults:
    query = args.get("query")

    chat_model = ChatOpenAI(
        model=HOSPITAL_AGENT_MODEL,
        temperature=0,
        http_client=HTTPX_CLIENT
    )

    hospital_rag_agent = create_openai_functions_agent(
        llm=chat_model,
        prompt=hospital_agent_prompt,
        tools=tools,
    )

    hospital_rag_agent_executor = AgentExecutor(
        agent=hospital_rag_agent,
        tools=tools,
        return_intermediate_steps=True,
        verbose=True,
    )

    # Call the Client function and get the raw response
    result = agent.execute(query)

    return CommandResults(
        outputs_prefix="XSOARAIAgent.Outputs",
        outputs=result,
    )


def main():
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    params = demisto.params()
    ai_model = params.get("model")
    api_key = params.get("apikey")
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    args = demisto.args()

    try:
        agent = Agent(model=ai_model, api_key=api_key)
        if command == "test-module":
            result = test_module(agent)
        elif command == "xsoar-ai-agent-execute":
            result = xsoar_ai_agent_execute_command(agent, args)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
        return_results(result)  # Returns either str, CommandResults and a list of CommandResults
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
