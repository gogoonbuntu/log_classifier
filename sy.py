import os, time, re

enc = set()
no_enc = set()
encs = set()
no_encs = set()
logs = {}
stats = {}
result1 = set() # GET, no encrypt
result2 = set() # GET, enc
result3 = set() # POST, no enc
result4 = set() # POST, enc
result5 = set() # GET, no query

result6 = set() # /uas?
result7 = set() # /uas/?
printed = set()
printedarr = set()

reg_enc = re.compile('[^\w\s\-\_\.\~\%\=]')
reg_url = re.compile('\"[^\"]* ')

# get query values in array
# and put CPID into two sets by checking encryption
def checkEncrypt(arr, aset, bset):
        global logs
        _cpid = ''
        _name = ''
        _enc = True
        _prob = ''
        #print(arr)
        find = arr[0].find
        for idx, elem in enumerate(arr):
                if elem[0:4] == 'CPID':
                        _cpid = elem[5:]
                        if not _enc:
                                break

                if idx > 0 and reg_enc.findall(elem):
                        _prob = elem
                        _enc = False

        if(_cpid != ''):
                if(find('GET')>-1):
                        _line = '[GET] '+_cpid+(' Enc' if _enc else ' NoEnc')
                        _log = " "+_name+" "+str(arr)

                        if (_line not in aset or _line not in bset):
                                logs.update({_line:_log+"\n"})

                        if(_enc):
                                bset.add(_line)
                                addstat(_enc, _line)
                        else:
                                aset.add(_line)
                                addstat(_enc, _line)

                elif(find('POST')>-1):
                        _line = '[POST] '+_cpid+(' Enc' if _enc else ' NoEnc')
                        _log = " "+_name+" "+str(arr)
                        if(_line not in aset or _line not in bset):
                                logs.update({_line:_log+'\n'})
                        if(_enc):
                                bset.add(_line)
                                addstat(_enc, _line)
                        else:
                                aset.add(_line)
                                addstat(_enc, _line)
                else:
                        print("nono : ",_cpid)

        return aset, bset

# count how many logs of each CPIDs
def addstat(_enc, _line):
        global stats
        if(_line not in stats):
                stats.update({_line:1})
        else:
                stats[_line]+=1

# check uas/? or uas?
def checkSlash(filename):
        print(filename)
        global result6, result7, enc, no_enc, encs, no_encs
        with open(filename, 'r') as thisFile:
                thisContents = thisFile.read()
                thisLines = thisContents.split('\n')
                for aline in thisLines :
                        #aline = aline[40:]
                        rf = reg_url.findall
                        if (rf(aline)):
                                aline = rf(aline)[0][1:-1]
                        qpoint = aline.find('?')
                        if(qpoint>0):
                                tarr = aline.split('&')
                                # uas?
                                if(aline[qpoint-1]=='s'):
                                        no_enc, enc = checkEncrypt(tarr, no_enc, enc)

                                # uas/? , -s for slash
                                elif(aline[qpoint-1]=='/'):
                                        no_encs, encs = checkEncrypt(tarr, no_encs, encs)
                                else:
                                        result5.add(tarr[0])


starttime = time.time()

fileList = os.listdir('172.16.25.226/access')
fileList2 = os.listdir('172.16.25.227/access')

for afile in fileList:
        if afile[0:18]=='access_log.2020-12' and afile[-3:]=='txt':
                checkSlash('172.16.25.226/access/'+afile)

for afile in fileList2:
        if afile[0:18]=='access_log.2020-12' and afile[-3:]=='txt':
                checkSlash('172.16.25.227/access/'+afile)

# remove not_encoded CPIDs in encoded CPIDs
removing = set()
for a in enc:
        for b in no_enc:
                if a[1] == 'G':
                        if a[0:16] == b[0:16]:
                                removing.add(a)
                if a[1] == 'P':
                        if a[0:17] == b[0:17]:
                                removing.add(a)

for a in removing:
        enc.remove(a)

removing = set()
for a in encs:
        for b in no_encs:
                if a[1] == 'G':
                        if a[0:16] == b[0:16]:
                                removing.add(a)
                if a[1] == 'P':
                        if a[0:17] == b[0:17]:
                                removing.add(a)

for a in removing:
        encs.remove(a)

for a in enc:
        if a[1]=='G':
                result2.add(a[6:16])
        elif a[1]=='P':
                result4.add(a[7:17])

for b in no_enc:
        if b[1] == 'G':
                result1.add(b[6:16])
        elif b[1] == 'P':
                result3.add(b[7:17])

for a in encs:
        if a[1]=='G':
                result2.add(a[6:16])
        elif a[1]=='P':
                result4.add(a[7:17])

for b in no_encs:
        if b[1] == 'G':
                result1.add(b[6:16])
        elif b[1] == 'P':
                result3.add(b[7:17])

result6 = result6.union(no_enc, enc)
result7 = result7.union(no_encs, encs)

### Recording!!
with open('results.txt', 'w') as f:
        f.write("[uas?] : "+str(result6)+"\n")
        f.write("in total : "+str(len(result6)) + "\n\n")
        f.write("[uas/?] : " + str(result7) + "\n")
        f.write("in total : "+str(len(result7)) + "\n\n")
        f.write("[GET, NoEnc] : "+str(result1)+"\n")
        f.write("case 1 : "+str(len(result1)) + "\n\n")
        f.write("[GET, Enc] : "+str(result2)+"\n")
        f.write("case 2 : "+str(len(result2)) + "\n\n")
        f.write("[POST, NoEnc] : "+str(result3)+"\n")
        f.write("case 3 : " + str(len(result3)) + "\n\n")
        f.write("[POST, Enc] : "+str(result4)+"\n")
        f.write("case 4 : " + str(len(result4)) + "\n\n")
        f.write('Reference Data of Each result:'+"\n")
        for (a, b) in sorted(logs.items()):
                f.write("  "+a+" "+str(b)+"\n")
        f.write("in total : " + str(len(logs)) + "\n\n")
        f.write('Counts of Each CPID:'+'\n')
        sum = 0
        for (a, b) in sorted(stats.items()):
                f.write("  "+a+" : "+str(b)+"\n")
                sum+=b
        f.write("in total : " + str(len(stats)) + " CPIDs, "+str(sum)+" logs."+ "\n")


with open('exceptions.txt', 'w') as f:
        for a in result5:
                f.write("  "+a+"\n")

print("execute time : ", time.time() - starttime)
