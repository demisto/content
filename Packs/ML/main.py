#Creating GUI with tkinter
import tkinter 
from tkinter import *
import pandas as pd
import os
import torch
import pickle
from abc import ABC
import yaml
from pytorch_pretrained_bert import BertTokenizer
import numpy as np
from abc import abstractmethod
import warnings
warnings.filterwarnings("ignore")
import webbrowser

#
#
class Recommender:
    """ Base class that defines the interface for all recommenders """

    def __init__(self, config):
        self.config = config

    @abstractmethod
    def getName(self):
        """
        :return: Return the name of the recommender
        """
        return ""

    @abstractmethod
    def predict(self, query):
        """ Makes prediction with the query

        :param query: A query from POST
        :return: List of (prediction, score) pairs
        """
        return []

    @abstractmethod
    def refresh(self):
        return



class BertRecommender(Recommender, ABC):
    """ Makes KB recommendations based on BERT model """

    def __init__(self, config):
        super(BertRecommender, self).__init__(config)

        # Read from configuration
        dataDir = config.get('dataDir', '')
        modelFile = config.get('bert.model', 'model.pt')
        labelMapFile = config.get('bert.labelMap', 'label_map.pkl')
        self.topN = config.get('bert.topN', 5)
        self.maxSequence = config.get('bert.maxSequence', 120)

        # load pre-trained model directly from file without re-training the file
        with open(os.path.join(dataDir, modelFile), "rb") as f:
            self.model = torch.load(f, map_location=torch.device('cpu'))

        with open(os.path.join(dataDir, labelMapFile), "rb") as f:
            self.labelMap = pickle.load(f)

        # Initialize tokenizer
        self.tokenizer = BertTokenizer.from_pretrained('bert-base-cased', do_lower_case=False)

        return

    def getName(self):
        return "BERT"
    
#    def load_model(self,folder_path):
#    # load pre-trained model directly from file to CPU without re-training the file
#        model = torch.load(folder_path+delimiter+"CXT_model.pt",map_location='cpu')
#        
#        with open(folder_path + delimiter + "CXT_label.pkl", "rb") as f:
#            label_map = pickle.load(f)
#        
#        return model, label_map


    def _tokenize(self, query):
        """ Tokenize the query """

        tokens = self.tokenizer.tokenize(query)
        if len(tokens) > self.maxSequence - 2:
            tokens = tokens[:(self.maxSequence - 2)]
        tokens = ["[CLS]"] + tokens + ["[SEP]"]

        inputIds = self.tokenizer.convert_tokens_to_ids(tokens)
        inputMask = [1] * len(inputIds)

        # Padding the rest of inputIds and inputMask with 0
        padding = [0] * (self.maxSequence - len(inputIds))
        inputIds += padding
        inputMask += padding

        return inputIds, inputMask

    def predict(self, query):

        # Make a reverse map from label to KB ID
        label2kbId = {v: k for k, v in self.labelMap.items()}

        # Tokenize the query
        tokenizedQuery, tokenMask = self._tokenize(query)

        # Wrap tokenized query in tensor of pytorch
        inputTensor = torch.tensor([tokenizedQuery]).to('cpu')
        inputMaskTensor = torch.tensor([tokenMask]).to('cpu')

        # Initialize model
        self.model.eval()

        # Made prediction
        with torch.no_grad():
            logits = self.model(inputTensor, None, inputMaskTensor, labels=None)
        logits[np.isnan(logits)] = -999999

        # Pick top N predictions
        predictions = logits.detach().cpu().numpy()[0]
        topIdx = (-predictions).argsort()[:self.topN]

        # Sums up top scores for normalization
        # (also bump 2nd ranked score to at least 0.2)
        #print("BERT raw scores: ", [predictions[i] for i in topIdx])
        totalScore = np.asarray([max(predictions[i], 0) for i in topIdx]).sum()
        results = [(label2kbId[i], (predictions[i]/totalScore).item()) for i in topIdx]
        results[1] = (results[1][0], max(0.20001, results[1][1]))

        return results


def callback(url):
    webbrowser.open_new(url)

def display_url_list(res):
    #res is a list of urls
    result = ("Please see recommended articles regarding your query in the new window\n")
    
    # link1 = Label(base, text="link1", fg="blue", cursor="hand1")
    link1 = Label(base)
    link1.pack()
    link1.bind("<Button-1>",callback(res[0]))
    
    link2 = Label(base)
    link2.pack()
    link2.bind("<Button-2>",callback(res[1]))
    return result


def chatbot_response(msg):
    prediction = BERT.predict(msg)
        
    url_list = [ ]
    
  
    for item in prediction:
        if item[0] not in showed:
            showed.add(kb_dict[item[0]])
            if kb_dict[item[0]] not in url_list:
                url_list.append(kb_dict[item[0]])
        if len(url_list)==2:
            break
                
    
    return(display_url_list(url_list))
    




def send():
    msg = EntryBox.get("1.0",'end-1c').strip()
    EntryBox.delete("0.0",END)
    

    if msg != '':
        ChatLog.config(state=NORMAL)
        ChatLog.insert(END, "You: " + msg + '\n\n')
        ChatLog.config(foreground="#442265", font=("Verdana", 12 ))
        
        if msg in greeting_dict:
            if msg=='Thanks' or msg=='thanks':
                res = greeting_dict[msg]
            else:
                res = greeting_dict[msg]+"."+" How may I help you?\n"
            ChatLog.insert(END, "Bot: " + res + "\n\n")

        else:
            res = chatbot_response(msg)
            
            ChatLog.insert(END, "Bot: " + res + '\n\n'+"Are these links helpful?\n You may close the window if your questions are answered. Otherwise you can continue to ask a new question.\n\n")

        ChatLog.config(state=DISABLED)
        ChatLog.yview(END)


delimiter = os.sep

with open('config.yml') as configFile:
    config = yaml.load(configFile, Loader=yaml.Loader)

    
global BERT
BERT = BertRecommender(config)



data_dir = 'corpus'
data_df = pd.read_csv(data_dir+delimiter+'greeting.csv')

global greeting_dict
greeting_dict = dict(zip(data_df['Question'],data_df['Answer']))

global kb_content, kb_dict
kb_content = pd.read_csv(data_dir+delimiter+'article_content.csv')
kb_dict = dict(zip(kb_content['referenceId'],kb_content['url']))

global showed
showed = set()


global base

base = Tk()
base.title("PANW chatbot")
base.geometry("400x500")
base.resizable(width=FALSE, height=FALSE)



#Create Chat window
ChatLog = Text(base, bd=0, bg="white", height="8", width="50", font="Arial",)

ChatLog.config(state=DISABLED)

#Bind scrollbar to Chat window
scrollbar = Scrollbar(base, command=ChatLog.yview, cursor="heart")
ChatLog['yscrollcommand'] = scrollbar.set

#Create Button to send message
SendButton = Button(base, font=("Verdana",12,'bold'), text="Send", width="12", height=5,
                    bd=0, bg="blue", activebackground="green",fg='white',
                    command= send )

#Create the box to enter message
EntryBox = Text(base, bd=0, bg="white",width="29", height="5", font="Arial")
#EntryBox.bind("<Return>", send)


#Place all components on the screen
scrollbar.place(x=376,y=6, height=386)
ChatLog.place(x=6,y=6, height=386, width=370)
EntryBox.place(x=128, y=401, height=90, width=265)
SendButton.place(x=6, y=401, height=90)

base.mainloop()



