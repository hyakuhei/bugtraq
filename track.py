import sys,os,urllib2,mechanize,re,bs4,argparse


#This sets up the arguments.
parser = argparse.ArgumentParser(description="Usage is: bugtrack.py -v VENDOR. For best results use both the -d and the -s options.")
parser.add_argument("-v", "--Vendor", action='store', dest="Vendor", help="This is the vendor you want to search for. This is required", required = True)
parser.add_argument("-t", "--Title", action='store', help="This is the Title/Product from the vendor you are searching for. " ,dest="Title")
parser.add_argument("-r", "--Version", action='store', help="This is the version of the Product you are searching for." ,dest="Version")
parser.add_argument("-s", "--Summary", action='store_true', help="This provides the first 100 hits, includes both Title and url.")
parser.add_argument("-f", "--File", action='store', dest='File', help="This provides the option to save results to a file")
parser.add_argument("-d", "--Detailed", action='store_true', help="This provides a level of detail about each hit. Including CVE Number, Local and Remote exploit, and the exploit itself")
args = parser.parse_args()

#This sets the Title and Version to NULL character so that the URL will work correctly if they are specified.
if args.Title is None:
    args.Title = ""
if args.Version is None:
    args.Version = ""
fileName = args.File

#This creates the url and adds in the Vendor/Title/Version, then generates this inital request and reads it.
url = "http://www.securityfocus.com/cgi-bin/index.cgi?o=0&l=500&c=12&op=display_list&vendor=%s&title=%s&version=%s&CVE=" % (args.Vendor,args.Title,args.Version)
br = mechanize.Browser()
response = br.open(url)

def Main():    
    if args.Summary is True:
        Summary()
    if args.Detailed is True:
        Detailed()

def Summary():
    soup3 = bs4.BeautifulSoup(response.read())
    #This finds each link on the page that is a title and records the title. 
    for vulns in soup3.find_all('a'):
        title = re.search(r'class="headline">(.+)</span>',str(vulns))
        if title:
            if args.File is None:
                print title.group(1)
            else:
                f = open(fileName,'a')
                f.write(title.group(1))
                f.write("\n")
                f.close()
    #This finds the URL's for each and records them with the title so you can view together.               
        link = re.search(r'/bid/\d+">(http.+)</a',str(vulns))
        if link:
            if args.File is None:
                print link.group(1)
            else:
                f = open(fileName,'a')
                f.write(link.group(1))
                f.write("\n")
                f.close()
    
    if args.File is True:
        f = open(fileName,'a')
        f.write("\n\n")
        f.close()
    
def Detailed():
# This Reads the page in and pulls the data out.
    for link in br.links(url_regex="/bid"):
        response1 = br.follow_link(link)
        pageData = response1.read()
            
        soup = bs4.BeautifulSoup(pageData)
        stripData = soup.get_text()
        
        #Gets the Vulnerability title
        vulnTitle = re.search(r'<span class="title">(.*)</span>',pageData)
        if vulnTitle:
            if args.File is None:
                print "Title:", vulnTitle.group(1)
            else:
                f = open(fileName,'a')
                f.write("Title:"),
                f.write(vulnTitle.group(1))
                f.write("\n")
                f.close()
        
        
        #Gets CVE Number    
        CVENum = re.search(r'CVE[\w-]+',stripData)
        if CVENum:
            if args.File is None:
                print "CVE Number:", CVENum.group()
            else:
                f = open(fileName,'a')
                f.write("CVE Number:"),
                f.write(CVENum.group())
                f.write("\n")
                f.close()
        else:
            if args.File is None:
                print "No CVE Number Present"
            else:
                f = open(fileName,'a')
                f.write("No CVE Number Present")
                f.write("\n")
                f.close()
                
        #Checks value of Remote
        remotePossible = re.search(r'(Remote:)\s+(\w+)',stripData)
        if remotePossible:
            if args.File is None:
                print remotePossible.group(1), remotePossible.group(2)
            else:
                f = open(fileName,'a')
                f.write(remotePossible.group(1)),
                f.write(remotePossible.group(2))
                f.write("\n")
                f.close()
       
        #Checks value of Local    
        localPossible = re.search(r'(Local:)\s+(\w+)',stripData)
        if localPossible:
            if args.File is None:
                print localPossible.group(1), localPossible.group(2)
            else:
                f = open(fileName,'a')
                f.write(localPossible.group(1)),
                f.write(localPossible.group(2))
                f.write("\n")
                f.close()
        # This pulls the data from the exploit page
        for link2 in br.links(url_regex="/exploit"):
            response2 = br.follow_link(link2)
            pageData2 = response2.read()
            soup2 = bs4.BeautifulSoup(pageData2)
            
            exploitInfo = soup2.findAll('div', {"id" : "vulnerability"})
            pageClean = str(exploitInfo).replace('<br/>','\n')
            exploitData = re.search(r'</span>(.+)<ul>(.+)</ul>',pageClean,re.DOTALL)
            
            if exploitData:
                if args.File is None:
                    print exploitData.group(1)
                    print exploitData.group(2)
                else:
                    f = open(fileName,'a')
                    f.write(exploitData.group(1))
                    f.write(exploitData.group(2))
                    f.write("\n")
                    f.close()

if __name__ == "__main__":
    Main()