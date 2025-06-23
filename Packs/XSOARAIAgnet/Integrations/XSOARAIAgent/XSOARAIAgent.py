from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
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
import httpx
import contextlib
from urllib3.exceptions import InsecureRequestWarning


""" CONSTANTS """
NEO4J_URI = "bolt://127.0.0.1/:7687"
NEO4J_USERNAME = "neo4j"
NEO4J_PASSWORD = "contentgraph"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
HTTPX_CLIENT = httpx.Client(verify=False)
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
statement (e.g. WITH i as integration, i.name as integration_name)
If you need to divide numbers, make sure to
filter the denominator to be non zero.

Examples:
# Which integration has the most commands?
MATCH (i:Integration)-[r:HAS_COMMAND]->(c:Command)
RETURN i.name as integration_name, count(c) as command_count
ORDER by command_count desc
LIMIT 1

# How many packs depends on the Base pack?
MATCH (p:Pack)-[d:DEPENDS_ON]->(m:Pack {name: "Base"})
RETURN count(p)

# How many integrations can fetch incidents?
MATCH (i:Integration)
WHERE i.is_fetch
RETURN count(i) as integration_count

# What is the number of deprecated integrations?
MATCH (i:Integration)
WHERE i.deprecated
RETURN count(i)

Make sure to use IS NULL or IS NOT NULL when analyzing missing properties.
Never return embedding properties in your queries. You must never include the
statement "GROUP BY" in your query. Make sure to alias all statements that
follow as with statement (e.g. WITH i as integration, c.name as
integration_name)
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

Never say you don't have the right information if there is data in
the query results. Always use the data in the query results.

Helpful Answer:
"""

""" AGENT CLASS """


class Agent:
    """
    """

    def __init__(self, model, api_key):
        self.model = model
        self.api_key = api_key
        self.tools = [
            Tool(
                name="Question",
                func=self.generate_question_cypher_chain().invoke,
                description="""Useful for answering questions about integrations,
                scripts, incident types, incident fields, layouts, classifiers, mappers.
                Use the entire prompt as input to the tool. For instance,
                if the prompt is "How to configure the Virus Total integration?",
                the input should be "How to configure the Virus Total integration?".
                """,
            ),
            Tool(
                name="ExecuteCommand",
                func=self.execute_command,
                description="""Useful for requests to run integration commands or scripts. 
                Use the entire prompt as input to the tool. 
                For instance, if the prompt is "Provide details about incident ID 23 in ServiceNow?",
                the input should be "Provide details about incident ID 23 in ServiceNow?".
                """,
            ),
            Tool(
                name="CreateIncident",
                func=self.create_incident,
                description="""Useful for requests to create an incident.
                Use the entire prompt as input to the tool. For instance,
                if the prompt is "Create an incident of type demo-incident",
                the input should be "Create an incident of type demo-incident".
                """,
            ),
            Tool(
                name="CreateIndicator",
                func=self.create_indicator,
                description="""Usefully for requests to create an indicator.
                Use the entire prompt as input to the tool. For instance,
                if the prompt is "Create an incident of type domain with the value 1.1.1.1?",
                the input should be "Create an incident of type domain with the value 1.1.1.1?".
                """,
            ),
        ]

    def generate_question_cypher_chain(self) -> GraphCypherQAChain:
        cypher_generation_prompt = PromptTemplate(
            input_variables=["schema", "question"], template=CYPHER_GENERATION_TEMPLATE
        )
        qa_generation_prompt = PromptTemplate(
            input_variables=["context", "question"], template=QA_GENERATION_TEMPLATE
        )

        return GraphCypherQAChain.from_llm(
            cypher_llm=ChatOpenAI(model=self.model, api_key=self.api_key, http_client=HTTPX_CLIENT, temperature=0),
            qa_llm=ChatOpenAI(model=self.model, api_key=self.api_key, http_client=HTTPX_CLIENT, temperature=0),
            graph=connect_to_graph(),
            verbose=True,
            qa_prompt=qa_generation_prompt,
            cypher_prompt=cypher_generation_prompt,
            validate_cypher=True,
            top_k=100,
            allow_dangerous_requests=True,
        )

    @staticmethod
    def execute_command(query: str) -> ...:
        demisto.debug(f"called execute command with: {query=}")
        demisto.debug("Executing command")
        return f"Command {query} was executed successfully.\n"

    @staticmethod
    def create_incident(query: str) -> ...:
        demisto.debug(f"called create incident with: {query=}")
        demisto.debug("Generating incident")
        new_incident = demisto.createIncidents([{"name": "xsoar ai incident"}])
        return new_incident

    @staticmethod
    def create_indicator(query: str) -> ...:
        demisto.debug(f"called create indicator with: {query=}")
        demisto.debug("Generating indicator")
        return f"New indicator with id {randint(0, 999)} was created.\n"

    def test(self):
        ...

    def execute(self, query: str) -> dict[str, Any]:
        demisto.debug(f'The Agent will execute query: {query} with model: {self.model}')

        chat_model = ChatOpenAI(
            model=self.model,
            api_key=self.api_key,
            http_client=HTTPX_CLIENT,
            temperature=0,
        )
        xsoar_rag_agent = create_openai_functions_agent(
            llm=chat_model,
            prompt=XSOAR_AGENT_PROMPT,
            tools=self.tools,
        )
        xsoar_rag_agent_executor = AgentExecutor(
            agent=xsoar_rag_agent,
            tools=self.tools,
            return_intermediate_steps=True,
            verbose=True,
        )
        demisto.debug("hey success")

        name = query
        execution = xsoar_rag_agent_executor.invoke({"input": name})

        return execution


""" HELPER FUNCTIONS """


def connect_to_graph():
    graph = Neo4jGraph(
        url=NEO4J_URI,
        username=NEO4J_USERNAME,
        password=NEO4J_PASSWORD,
    )

    graph.refresh_schema()

    return graph


# Disable SSL


old_merge_environment_settings = requests.Session.merge_environment_settings


@contextlib.contextmanager
def no_ssl_verification():
    opened_adapters = set()

    def merge_environment_settings(self, url, proxies, stream, verify, cert):
        # Verification happens only once per connection so we need to close
        # all the opened adapters once we're done. Otherwise, the effects of
        # verify=False persist beyond the end of this context manager.
        opened_adapters.add(self.get_adapter(url))

        settings = old_merge_environment_settings(self, url, proxies, stream, verify, cert)
        settings['verify'] = False

        return settings

    requests.Session.merge_environment_settings = merge_environment_settings

    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', InsecureRequestWarning)
            yield
    finally:
        requests.Session.merge_environment_settings = old_merge_environment_settings

        for adapter in opened_adapters:
            try:
                adapter.close()
            except:
                pass


with no_ssl_verification():
    XSOAR_AGENT_PROMPT = hub.pull("hwchase17/openai-functions-agent")

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

    result = agent.execute(query)

    return CommandResults(
        readable_output=tableToMarkdown("Result", result),
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
