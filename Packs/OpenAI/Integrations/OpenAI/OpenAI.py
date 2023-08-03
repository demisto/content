import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
### pack version: 1.2.0


import json
import urllib3
import hashlib
# Imports for LangChain - https://python.langchain.com/docs/get_started/introduction.html
from langchain.llms import OpenAI,AzureOpenAI
from langchain.embeddings import OpenAIEmbeddings
from langchain.document_loaders import UnstructuredFileLoader
from langchain.vectorstores import FAISS
from langchain.chains import ConversationalRetrievalChain
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.prompts import PromptTemplate
from langchain.chains.summarize import load_summarize_chain
from tempfile import NamedTemporaryFile

urllib3.disable_warnings()

PREFIX = "openai"  # prefix at front of all commands


''' CLIENT CLASS '''


class Client(BaseClient):
    """
        Client class to interact with the OpenAI and Azure OpenAI APIs
    """
    def __init__(self, api_key: str, base_url: str, proxy: bool, is_azure: bool, verify: bool, version: str):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)
        self.api_key = api_key
        self.base_url = base_url
        self.is_azure = is_azure
        self.version = version
        self.headers = {"Content-Type": "application/json"}
        if self.is_azure:  # Azure OpenAI
            self.headers["api-key"] = self.api_key
        else:  # standard api.openai.com
            self.headers["Authorization"] = f"Bearer {self.api_key}"

    def completions(self, prompt: str, model: str = "text-davinci-003", temperature: float = 0.2,
                    max_tokens: int = 256, top_p: float = 1, frequency_penalty: int = 0,
                    presence_penalty: int = 0, best_of: int = 1, stop: str = None) -> dict:
        """
            Enter an instruction and watch the OpenAI API respond with a completion that attempts to match the context
            or pattern you provided, using the 'completions' endpoint.

            :type prompt: ``str``
            :param prompt: Instruction
            :type model: ``str``
            :param model: The model which will generate the completion.
            :type temperature: ``float``
            :param temperature: Controls randomness: Lowering results in less random completions.
            :type max_tokens: ``int``
            :param max_tokens: The maximum number of tokens to generate.
            :type top_p: ``float``
            :param top_p: Controls Diversity via nucleus sampling
            :type frequency_penalty: ``int``
            :param frequency_penalty: How much to penalize new tokens based on their existing frequency in the text so far.
            :type presence_penalty: ``int``
            :param presence_penalty: How much to penalize new tokens based on whether they appear in the text so far.
            :type best_of: ``int``
            :param best_of: Generates best_of completions server-side and returns the "best"
            :type stop: ``str``
            :param stop: The returned text won't contain the stop sequence.

            :return: response of the OpenAI Completion API
            :rtype: ``dict``
        """

        # available API params for OpenAI: https://platform.openai.com/docs/api-reference/completions/create
        # available API params for Azure OpenAI: https://learn.microsoft.com/en-us/azure/cognitive-services/openai/reference#completions
        data = {
            "prompt": prompt,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "top_p": top_p,
            "frequency_penalty": frequency_penalty,
            "presence_penalty": presence_penalty,
            "best_of": best_of,
            "stop": stop
        }
        if self.is_azure:  # Azure OpenAI
            url_suffix = f"openai/deployments/{model}/completions?api-version={self.version}"
        else:  # standard api.openai.com
            data["model"] = model
            url_suffix = "v1/completions"
        return self._http_request(
            method='POST', url_suffix=url_suffix, json_data=data,
            headers=self.headers, resp_type='json', ok_codes=(200,)
        )

    def chatgpt(self, prompt: str, model: str = "gpt-3.5-turbo") -> dict:
        """
            Send prompt to ChatGPT using the 'chat/completions' endpoint.

            Args:
                prompt (str): Input to ChatGPT
                model (str): The model which will generate the chat response

            Returns:
                dict: HTTP response from the OpenAI Chat API
        """
        options = {
            "max_tokens": 1000,
            "messages": [{
                "role": "user",
                "content": prompt
            }]
        }
        if self.is_azure:  # Azure OpenAI
            url_suffix = f"openai/deployments/{model}/chat/completions?api-version={self.version}"
        else:  # standard api.openai.com
            options["model"] = model
            url_suffix = "v1/chat/completions"
        return self._http_request(
            method='POST', url_suffix=url_suffix,
            json_data=options, headers=self.headers,
            resp_type="json", ok_codes=(200,)
        )


''' HELPER FUNCTIONS '''


def chatgpt_output(response) -> CommandResults:
    """
        Convert response from ChatGPT to a human readable format in markdown table

        :return: CommandResults return output of ChatGPT response
        :rtype: ``CommandResults``
    """
    if response and isinstance(response, dict):
        rep = json.dumps(response)
        repJSON = json.loads(rep)
        model = repJSON.get('model')
        createdTime = repJSON.get('created')
        id = repJSON.get('id')
        choices = repJSON.get('choices', [])[0].get('message', {}).get('content', "").strip('\n')
        promptTokens = repJSON.get('usage', {}).get('prompt_tokens')
        completionTokens = repJSON.get('usage', {}).get('completion_tokens')
        totalTokens = repJSON.get('usage', {}).get('total_tokens')
        context = [{'id': id, 'Model': model,
                    'ChatGPT Response': choices, 'Created Time': createdTime,
                    'Number of Prompt Tokens': promptTokens,
                    'Number of Completion Tokens': completionTokens,
                    'Number of Total Tokens': totalTokens
                    }]

        markdown = tableToMarkdown(
            'ChatGPT API Response',
            context,
            date_fields=['Created Time'],
        )
        results = CommandResults(
            readable_output=markdown,
            outputs_prefix='OpenAI.ChatGPTResponse',
            outputs_key_field='id',
            outputs=context
        )
        return results
    else:
        raise DemistoException('Error in results')


def process_text_input_args(text: str, entry_id: str) -> list:
    """
        Process and return list of documents so LangChain can work with the input data

        Args:
            text (str): text string to load
            entry_id (str): XSOAR entry ID of file to load

        Returns:
            list: list of loaded documents
    """
    if text and entry_id:
        raise DemistoException('Only supply one of arguments "text" and "entry_id".')
    elif not text and not entry_id:
        raise DemistoException('Either argument "text" or argument "entry_id" is required. ' \
                               'If no additional input data besides the prompt is required for your use case, ' \
                               f'use either command `{PREFIX}-chatgpt` or `{PREFIX}-completions` instead.')
    # https://python.langchain.com/docs/modules/data_connection/document_transformers/text_splitters/recursive_text_splitter
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=0)
    if text:  # string text input
        docs = text_splitter.create_documents([text])
    else:  # text file input
        docs = load_unstructured_file(entry_id, text_splitter)
    return docs


def load_unstructured_file(entry_id: str, text_splitter: RecursiveCharacterTextSplitter) -> list:
    """
        Use LangChain UnstructuredFileLoader to load file contents based on entry ID

        Args:
            entry_id (str): XSOAR entry ID of file to load
            text_splitter (RecursiveCharacterTextSplitter): LangChain TextSplitter object

        Returns:
            list: list of loaded documents
    """
    file = demisto.getFilePath(entry_id)
    file_path = file.get('path')
    with open(file_path, 'r') as f:
        contents = f.read()
    with NamedTemporaryFile() as tmp:
        tmp.write(contents)
    # https://python.langchain.com/docs/modules/data_connection/document_loaders/integrations/unstructured_file
    loader = UnstructuredFileLoader(tmp.name)
    document = loader.load()
    docs = text_splitter.split_documents(document)
    return docs


''' COMMAND FUNCTIONS '''


def test_module(client: Client, model: str) -> str:
    """
        Tests OpenAI API connectivity and authentication
    """
    test_prompt = "Can I connect to the OpenAI api?"
    if model:
        result = client.completions(prompt=test_prompt, model=model)
    else:
        result = client.completions(prompt=test_prompt)
    if result:
        return 'ok'
    else:
        return 'Did not receive a response from OpenAI API'


def chatgpt_send_prompt_command(client: Client, prompt: str,
                                model: str = "gpt-3.5-turbo") -> CommandResults:
    """
        Command to send prompts to OpenAI ChatGPT API
        and receive a response converted into json then
        returned to Output function to convert it to markdown table

        :type client: ``Client``
        :param prompt:  arguments
    """
    if not prompt:
        raise DemistoException('the prompt argument cannot be empty.')

    chatgpt_response = client.chatgpt(prompt, model=model)
    return chatgpt_output(chatgpt_response)


def completions_command(client: Client, args: dict) -> CommandResults:
    """
        Enter an instruction and watch the OpenAI API respond with a completion that attempts to match the context
        or pattern you provided, using the 'completions' endpoint.

        :type client: ``Client``
        :param client: instance of Client class to interact with OpenAI API
        :type args: ``dict``
        :param args:  arguments

        :return: CommandResults instance of the OpenAI Completion API response
        :rtype: ``CommandResults``
    """
    prompt = args.get('prompt', False)

    if not prompt:
        raise ValueError('No prompt argument was provided')

    model = args.get('model', 'text-davinci-003')
    temperature = args.get('temperature', 0.2)
    max_tokens = args.get('max_tokens', 256)
    top_p = args.get('top_p', 1)
    frequency_penalty = args.get('frequency_penalty',0)
    presence_penalty = args.get('presence_penalty', 0)
    best_of = args.get("best_of", 1)
    stop = args.get("stop", None)

    response = client.completions(
        prompt=prompt, model=model, temperature=float(temperature),
        max_tokens=int(max_tokens), top_p=int(top_p),
        frequency_penalty=int(frequency_penalty), presence_penalty=int(presence_penalty),
        best_of=int(best_of), stop=stop
    )
    meta = None
    context = None

    if response and isinstance(response, dict):
        model = response.get('model')
        id = response.get('id')
        choices = response.get('choices', [])
        meta = f"Model {response.get('model')} generated {len(choices)} possible text completion(s)."
        context = [{'id': id, 'model': model, 'text': choice.get('text')} for choice in choices]

    return CommandResults(
        readable_output=tableToMarkdown('OpenAI - Completions', context, metadata=meta, removeNull=True),
        outputs_prefix='OpenAI.Completions',
        outputs_key_field='id',
        outputs=context,
        raw_response=response
    )


def answer_question_command(client: Client, args: dict) -> CommandResults:
    """
        Embed input data with LangChain, save to vectorstore, then use OpenAI LLM
        to answer a question based on the input data:
        https://python.langchain.com/docs/modules/chains/popular/chat_vector_db

        Args:
            client (Client): OpenAI client object
            args (dict): Arguments passed into the command

        Returns:
            str: Answer generated by the LLM
    """
    question = args.get("question")
    text = args.get("text", "")
    entry_id = args.get("entry_id", "")
    model = args.get("model")
    deployment = args.get("deployment")
    temperature = args.get("temperature")
    chat_history = args.get("chat_history", [])

    if client.is_azure:
        llm = AzureOpenAI(
            temperature=temperature,
            deployment_name=deployment,
            model_name=model
        )
    else:
        llm = OpenAI(temperature=temperature)

    # load in the documents to use to answer the question
    docs = process_text_input_args(text, entry_id)
    # create embeddings for the documents that will be used to answer the question
    embeddings = OpenAIEmbeddings(chunk_size=1)
    # generate unique ID for the input to save the index to
    if not entry_id:
        entry_id = hashlib.sha256(text.encode('utf-8'))
    # put the documents in a vectorstore - https://python.langchain.com/en/latest/modules/indexes/vectorstores/examples/faiss.html
    try:
        db = FAISS.load_local(f"faiss_index_{entry_id}", embeddings)  # load index from local copy to save time
    except RuntimeError:
        db = FAISS.from_documents(docs, embeddings)
        db.save_local(f"faiss_index_{entry_id}")  # save local copy of index

    # initialize QA chain
    qa = ConversationalRetrievalChain.from_llm(llm=llm, retriever=db.as_retriever(),
                                               verbose=False)
    # process chat history to pass into model, if supplied
    chat_hist = []
    if chat_history:
        if not isinstance(chat_history, list):
            chat_history = [chat_history]
        # reformat chat history in the format LangChain expects: array of tuples in format (question, answer)
        for item in chat_history:
            if "Question" not in item or "Answer" not in item:
                raise DemistoException("chat_history must be passed in in the format of the ${OpenAI.QA} context key " \
                                       "from previous `{PREFIX}-answer-question` command output.")
            chat_hist.append((item.get("Question"), item.get("Answer")))
    # run QA chain to get the answer
    result = qa({"question": question,
                 "chat_history": chat_hist})
    answer = result['answer']
    return CommandResults(
        outputs_prefix='OpenAI.QA',
        outputs={
            "Question": question,
            "Answer": answer
        },
        readable_output=f"**Answer**: {answer}"
    )


def summarize_command(client: Client, args: dict) -> CommandResults:
    """
        Summarize the provided input data using LangChain:
        https://python.langchain.com/docs/modules/chains/popular/summarize.html

        Args:
            client (Client): OpenAI client object
            args (dict): Arguments passed into the command

        Returns:
            str: Summary generated by the LLM
    """
    text = args.get("text", "")
    entry_id = args.get("entry_id", "")
    prompt = args.get("prompt", "")
    model = args.get("model")
    deployment = args.get("deployment")
    temperature = args.get("temperature")

    # load in the documents to summarize
    docs = process_text_input_args(text, entry_id)
    if client.is_azure:
        llm = AzureOpenAI(
            temperature=temperature,
            deployment_name=deployment,
            model_name=model
        )
    else:
        llm = OpenAI(temperature=temperature)
    # user supplied an additional prompt with specific instructions for how to summarize
    if prompt:
        if "{text}" not in prompt:
            raise DemistoException("Prompt must include the string {text} to indicate the position of the text input data within the prompt.")
        prompt = PromptTemplate(template=prompt, input_variables=["text"])
        chain = load_summarize_chain(llm=llm, chain_type="map_reduce",
                                     map_prompt=prompt, combine_prompt=prompt)
    else:
        chain = load_summarize_chain(llm=llm, chain_type="map_reduce")
    result = chain.run(docs).lstrip()  # remove leading whitespace from the result
    return CommandResults(
        outputs_prefix='OpenAI.Summary',
        outputs=result,
        readable_output=f"**Summary**: {result}"
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, runs command functions
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get('apikey')
    base_url = params.get('url', '')
    if base_url[-1] != '/':
        base_url = base_url + '/'
    is_azure = params.get('is_azure', False)
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    version = params.get('version', '2023-03-15-preview')
    test_model = params.get('test_model', '')

    # set env variable for API key
    os.environ["OPENAI_API_KEY"] = api_key
    # set additional required env variables for Azure OpenAI
    if is_azure:
        os.environ["OPENAI_API_TYPE"] = "azure"
        os.environ["OPENAI_API_VERSION"] = version
        os.environ["OPENAI_API_BASE"] = base_url

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(api_key=api_key, base_url=base_url, is_azure=is_azure, verify=verify, proxy=proxy, version=version)

        if command == 'test-module':
            # This is the call made when clicking the integration Test button.
            return_results(test_module(client, test_model))

        elif command == f'{PREFIX}-chatgpt':
            return_results(chatgpt_send_prompt_command(client, **args))

        elif command == f'{PREFIX}-completions':
            return_results(completions_command(client=client, args=args))

        elif command == f'{PREFIX}-answer-question':
            return_results(answer_question_command(client=client, args=args))

        elif command == f'{PREFIX}-summarize':
            return_results(summarize_command(client=client, args=args))

        else:
            raise NotImplementedError(f"command {command} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error("\n".join((f"Failed to execute {command} command.",
                                 "Error:", str(e))))


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
