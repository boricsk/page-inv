import requests
import re
from bs4 import BeautifulSoup, Comment, SoupStrainer
import click
from traitlets import default
from tkinter import *
import ttkbootstrap as tb
from tkinter import simpledialog,filedialog
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Messagebox
from pathlib import Path
import whois, json
import dns.resolver

DNSRecordTypes = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]
isDataLoad = False
def getCertificateInfo():
    try:
        domain = getDomainName(httpAddress.get())
        certRequest = f'https://crt.sh/?q={domain}&output=json'
        certResp = requests.get(certRequest)
        outputSource.delete(1.0, END)
        html = certResp.content.decode(getCharCoding(resp.headers['content-type']))
        JSONObject = json.loads(html)
        outputSource.insert(END,json.dumps(JSONObject, indent=2))
    except Exception as e:
        Messagebox.show_error(message=f"{e}",title="Navigation error")

def main():
    root = tb.Window(themename="superhero",title="WEB page investigate")
    root.geometry('1024x768')
    #menubar
    bttnBar = tb.Frame(root, style='primary.TFrame')
    bttnBar.pack(fill=X, pady=1, side=TOP)
    imgPath = Path(__file__).parent / 'assets'
    
    imageFiles = {'wordlist':'wordlist.png',
                  'comment':'comment-code.png',
                  'disk':'disk.png',
                  'dns':'fingerprint.png',
                  'qrcode':'qrcode.png',
                  'certificate':'cert.png',
                  'link':'link.png',
                  'image1':'image.png'}
    
    photoimages = []
    
    for key, val in imageFiles.items():
        _path = imgPath / val
        photoimages.append(tb.PhotoImage(name=key, file=_path))
        
    global btnWordlist
    btnWordlist = tb.Button(
        master = bttnBar,
        text = "Create wordlist",
        compound = LEFT,
        command = createWordlist,
        style="solid",
        image='wordlist',
        state=DISABLED
    )
    btnWordlist.pack(side = LEFT, ipadx = 5, ipady = 5, padx = (1,0),pady = 1)
    
    #show comments bttn
    global btnShowComments
    btnShowComments = tb.Button(
        master = bttnBar,
        text="Show comments",
        compound=LEFT,
        command=showComments,
        bootstyle="solid",
        image="comment",
        state=DISABLED
    )
    btnShowComments.pack(side = LEFT, ipadx = 5, ipady = 5, padx = (1,0),pady = 1)
    
    #receive DNS information bttn
    global btnDnsInfo
    btnDnsInfo = tb.Button(
        master = bttnBar,
        text="DNS info",
        compound=LEFT,
        command=receiveDnsData,
        style="solid",
        image="dns",
        state=DISABLED
    )
    btnDnsInfo.pack(side = LEFT, ipadx = 5, ipady = 5, padx = (1,0),pady = 1)
    
    #receive certification information bttn
    global btnShowCert
    btnShowCert = tb.Button(
        master = bttnBar,
        text="Cert info",
        compound=LEFT,
        command=getCertificateInfo,
        style="solid",
        image="certificate",
        state=DISABLED
    )
    btnShowCert.pack(side = LEFT, ipadx = 5, ipady = 5, padx = (1,0),pady = 1)
    
    #show links bttn
    global btnShowLinks
    btnShowLinks = tb.Button(
        master = bttnBar,
        text="Show links",
        compound=LEFT,
        command=showLinks,
        style="solid",
        image="link",
        state=DISABLED
    )
    btnShowLinks.pack(side = LEFT, ipadx = 5, ipady = 5, padx = (1,0),pady = 1)
    
    global btnShowImageLinks
    btnShowImageLinks = tb.Button(
        master = bttnBar,
        text="Show image links",
        compound=LEFT,
        command=showImageLinks,
        style="solid",
        image="image1",
        state=DISABLED
    )
    btnShowImageLinks.pack(side = LEFT, ipadx = 5, ipady = 5, padx = (1,0),pady = 1)
    
    #save output bttn
    global btnSave
    btnSave = tb.Button(
        master = bttnBar,
        text="Save output",
        compound=LEFT,
        command=saveOutput,
        style="solid",
        image="disk",
        state=DISABLED
    )
    btnSave.pack(side = RIGHT, ipadx = 5, ipady = 5, padx = (1,0),pady = 1)
    
    #input
    optionText = "Enter web address"
    optionAreaEntry = tb.Labelframe(root,text=optionText,padding=10)
    optionAreaEntry.pack(fill=X, expand=YES, anchor=N,padx=10, pady=10)
    
    global httpAddress 
    httpAddress = tb.Entry(master=optionAreaEntry)
    httpAddress.pack(side=LEFT, expand=YES, pady=5,fill=X)
    
    receiveDataBttn = tb.Button(master=optionAreaEntry, text="Send request", command=receiveHTMLData, style="success")
    receiveDataBttn.pack(side=RIGHT,padx=25,pady=5)
    
    #textarea
    httpFrame = tb.Labelframe(text="HTML Source")
    httpFrame.pack(expand=YES, anchor=N, padx=10, pady=10,fill=X )

    outFrame = tb.LabelFrame(text="Output")
    outFrame.pack(expand=YES, anchor=N, padx=10, pady=10,fill=X )
    
    global httpSource
    httpSource = tb.ScrolledText(master=httpFrame)
    httpSource.pack( side=LEFT, expand=YES, padx= 10,pady=10, fill=X, anchor=N)
    
    global outputSource
    outputSource = tb.ScrolledText(master=outFrame)
    outputSource.pack( expand=YES, padx= 10,pady=10, fill=X, anchor=N)

    
    root.mainloop()

def enableBttns():
    btnSave.configure(state=NORMAL)
    btnWordlist.configure(state=NORMAL)
    btnDnsInfo.configure(state=NORMAL)
    btnShowCert.configure(state=NORMAL)
    btnShowComments.configure(state=NORMAL)
    btnShowLinks.configure(state=NORMAL)
    btnShowImageLinks.configure(state=NORMAL)

def dissableBttns():
    btnSave.configure(state=DISABLED)
    btnWordlist.configure(state=DISABLED)
    btnDnsInfo.configure(state=DISABLED)
    btnShowCert.configure(state=DISABLED)
    btnShowComments.configure(state=DISABLED)
    btnShowLinks.configure(state=DISABLED)
    btnShowImageLinks.configure(state=DISABLED)

def showImageLinks():
    if isDataLoad:
        try:       
            imageLinks = []
            outputSource.delete('1.0',END)
            html = resp.content.decode(getCharCoding(resp.headers['content-type']))
            soup = BeautifulSoup(html,'html.parser',parse_only=SoupStrainer('img'))
            for link in soup:
                if link.has_attr('src'):
                    if link['src'] not in imageLinks:
                        outputSource.insert(END,link['src']+'\n')
                imageLinks.append(link['src'])
            imageLinks.clear()
        except Exception as e:
            Messagebox.show_error(message=f"{e}",title="Navigation error")
    else:
        Messagebox.ok(message='No data!')
        
def showLinks():

    try:       
        links = []
        outputSource.delete('1.0',END)
        html = resp.content.decode(getCharCoding(resp.headers['content-type']))
        soup = BeautifulSoup(html,'html.parser',parse_only=SoupStrainer('a'))
        for link in soup:
            if link.has_attr('href'):
                if link['href'] not in links:
                    outputSource.insert(END,link['href']+'\n')
            links.append(link['href'])
    except Exception as e:
        Messagebox.show_error(message=f"{e}",title="Navigation error")
        
def getCharCoding(contentType):
    startPos = 0
    i=0
    for char in contentType:
            if char == '=':
                startPos = i
            i += 1
    return contentType[startPos:]
    
    
def receiveHTMLData():
    global html, resp
    
    try:
        url = httpAddress.get()
        resp = requests.get(url)
        httpSource.delete('1.0',END)
        outputSource.delete(1.0, END)
        html = resp.content.decode(getCharCoding(resp.headers['content-type']))
        soup = BeautifulSoup(html,'html.parser')
        httpSource.insert(END,'HEADERS\n')
        httpSource.insert(END,resp.headers)
        httpSource.insert(END,'\n')
        httpSource.insert(END,'END OF HEADERS\n')
        httpSource.insert(END,soup.prettify())
        enableBttns()
    except Exception as e:
        Messagebox.show_error(message=f"{e}",title="Navigation error")

def createWordlist():
    try:
        charNum = simpledialog.askinteger('Character number','Enter minimum number of character (0=no limitation)',minvalue=0)
        wordList = []
        if charNum == 0:
            outputSource.delete('1.0',END)
            output = re.findall(r'\w+', BeautifulSoup(resp.content.decode(getCharCoding(resp.headers['content-type'])),'html.parser').get_text())
            for i in range(len(output)):
                if output[i] not in wordList:
                    wordList.append(output[i])
                    outputSource.insert(END,output[i]+'\n')
        else:
            outputSource.delete('1.0',END)
            output = re.findall(r'\w+', BeautifulSoup(resp.content.decode(getCharCoding(resp.headers['content-type'])),'html.parser').get_text())
            for i in range(len(output)):
                if len(output[i]) >= charNum:
                    if output[i] not in wordList:
                        wordList.append(output[i])
                        outputSource.insert(END,output[i]+'\n')
        
        wordList.clear()

    except Exception as e:
        Messagebox.show_error(message=f"{e}",title="Navigation error")

def showComments():

    try:       
        outputSource.delete('1.0',END)
        html = resp.content.decode(getCharCoding(resp.headers['content-type']))
        soup = BeautifulSoup(html,'html.parser')
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for i in range(len(comments)):
            outputSource.insert(END,comments[i]+'\n')
    except Exception as e:
        Messagebox.show_error(message=f"{e}",title="Navigation error")
 
def saveOutput():
    try:
        saveFile = filedialog.asksaveasfilename(title="Save output content")
        with open(saveFile,'w') as wr:
            wr.write(outputSource.get('1.0',END))
        wr.close
    except Exception as e:
        Messagebox.show_error(message=f"{e}",title="File I/O error")

def getDomainName(httpSource):
    startPos = 0
    iteration = 0
    for char in httpSource:
        if char == ':':
            startPos = iteration + 3
        iteration +=1
    return httpSource[startPos:]

def receiveDnsData():

    try:
        httpSource = httpAddress.get()
        outputSource.delete(1.0,END)
        if isRegistered(httpSource):
            whoisInfo = whois.whois(getDomainName(httpSource))
            outputSource.insert(END,'Whois info \n')
            outputSource.insert(END,whoisInfo.text)
            outputSource.insert(END,'\n')
            outputSource.insert(END,'DNS Enumeration\n')
            resolver = dns.resolver.Resolver()
            for RecType in DNSRecordTypes:
                try:
                    answers = resolver.resolve(getDomainName(httpSource), RecType)
                except dns.resolver.NoAnswer:
                    continue
                
                outputSource.insert(END,f"\nDNS Records for {httpSource} ({RecType})\n")
                
                for RecData in answers:
                    print(RecData)
                    outputSource.insert(END,RecData)
        else:
            outputSource.insert(END,'\nNot registered')
            
    except Exception as e:
        Messagebox.show_error(message=f"{e}",title="Communication error")

def isRegistered(domainName):
    try:
        w = whois.whois(domainName)
    except Exception:
        return False
    else:
        return True

if __name__ == '__main__':
    main()


