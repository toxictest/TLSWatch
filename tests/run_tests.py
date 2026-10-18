#!/usr/bin/env python3
"""Development-only hermetic regression suite; TLSWatch itself needs no Python.
Real OpenSSL certificates and validation; simulated network handshake transcripts.
"""
import os, pathlib, subprocess, tempfile, shutil, csv
ROOT=pathlib.Path(__file__).resolve().parents[1]
REAL=shutil.which('openssl'); passed=0

def check(label, condition):
    global passed
    if not condition: raise AssertionError(label)
    passed+=1; print('PASS',label)

def cmd(*args):
    return subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,check=True).stdout

with tempfile.TemporaryDirectory(prefix='tlswatch-test.') as td:
    t=pathlib.Path(td); (t/'bin').mkdir()
    cmd(REAL,'req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(t/'ca.key'),'-out',str(t/'ca.pem'),'-days','365','-subj','/CN=Test Root')
    for name,bits,days in [('good',2048,365),('soon',2048,1),('weak',1024,365)]:
        cmd(REAL,'req','-new','-newkey',f'rsa:{bits}','-nodes','-keyout',str(t/f'{name}.key'),'-out',str(t/f'{name}.csr'),'-subj','/CN=good.test')
        (t/'ext').write_text('subjectAltName=DNS:good.test,DNS:*.example.test,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n')
        cmd(REAL,'x509','-req','-in',str(t/f'{name}.csr'),'-CA',str(t/'ca.pem'),'-CAkey',str(t/'ca.key'),'-CAcreateserial','-out',str(t/f'{name}.pem'),'-days',str(days),'-extfile',str(t/'ext'))
    wrapper=t/'bin/openssl'
    wrapper.write_text('''#!/usr/bin/env python3
import os,sys,subprocess,pathlib
args=sys.argv[1:]; root=pathlib.Path(os.environ['FIX']); scenario=os.environ.get('SCENARIO','good'); real=os.environ['REAL_OPENSSL']
if args[0]=='s_client':
    if '-help' in args:
        sys.exit(1 if '-ssl2' in args or '-ssl3' in args else 0)
    if scenario=='offline': print('Connection refused'); sys.exit(1)
    if '-showcerts' in args or '-status' in args:
        cert='soon' if scenario=='soon' else 'weak' if scenario=='weak' else 'ca' if scenario=='self' else 'good'
        print((root/(cert+'.pem')).read_text())
        if scenario!='self': print((root/'ca.pem').read_text())
        if scenario=='revoked': print('OCSP Response Status: successful\\nCert Status: revoked')
        elif scenario!='missingocsp': print('OCSP Response Status: successful\\nCert Status: good')
        print('New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384');sys.exit(0)
    if '-cipher' in args and 'NULL' in args[args.index('-cipher')+1]:
        if scenario=='null': print('New, TLSv1.2, Cipher is NULL-SHA');sys.exit(0)
        print('alert handshake failure\\nNew, (NONE), Cipher is (NONE)');sys.exit(1)
    if scenario=='timeout': print('Connection timed out');sys.exit(124)
    if '-tls1' in args or '-tls1_1' in args:
        if scenario=='legacy': print('New, '+('TLSv1.1' if '-tls1_1' in args else 'TLSv1')+', Cipher is AES128-SHA');sys.exit(0)
        print('alert protocol version\\nNew, (NONE), Cipher is (NONE)');sys.exit(1)
    print('New, '+('TLSv1.2' if '-tls1_2' in args else 'TLSv1.3')+', Cipher is AES128-SHA');sys.exit(0)
if args[0]=='ciphers':
    if args[1].startswith('NULL'): print('TLS_AES_256_GCM_SHA384:NULL-SHA:NULL-SHA256');sys.exit(0)
    sys.exit(1)
if args[0]=='x509' and scenario=='expired' and '-enddate' in args:
    print('notAfter=Jan 1 00:00:00 2000 GMT');sys.exit(0)
if args[0]=='verify' and scenario=='missingchain':
    print('error 20 at 0 depth lookup: unable to get local issuer certificate');sys.exit(2)
sys.exit(subprocess.call([real]+args))
''');wrapper.chmod(0o755)
    base=os.environ|{'FIX':str(t),'REAL_OPENSSL':REAL,'PATH':str(t/'bin')+':'+os.environ['PATH']}
    def run(scenario='good',host='good.test',extra=()):
        dest=t/('out'+str(len(list(t.glob('out*')))))
        r=subprocess.run([str(ROOT/'tlswatch.sh'),'-d',host,'-o',str(dest),'--ca-file',str(t/'ca.pem'),'--no-color',*extra],env=base|{'SCENARIO':scenario},capture_output=True,text=True,timeout=60)
        check('run '+scenario+' exits 0',r.returncode==0)
        report=next(dest.glob('*/tls_full_report.txt')).read_text()
        return report,dest,r
    report,dest,r=run()
    check('expiry parsed','day(s) remaining' in report)
    check('hostname matched',"CN/SAN MATCH" in report)
    check('real CA validation','TRUSTED -' in report)
    check('legacy rejected','TLSv1.0 is disabled' in report)
    check('missing SSL2 not claimed safe','SSLv2 was removed' in report)
    check('incomplete coverage warning','INCOMPLETE COVERAGE' in report)
    check('no false modern-only claim','MODERN ONLY' not in report)
    check('NULL rejected not accepted','WEAK CIPHER ACCEPTED' not in report)
    check('OCSP present','OCSP STAPLED' in report)
    check('no ANSI in report','\x1b' not in report)
    check('four module headings once',all(report.count('Module '+str(i))==1 for i in range(1,5)))
    rows=list(csv.reader(next(dest.glob('*/tls_audit_summary.csv')).open()))
    check('CSV dimensions',len(rows)==2 and len(rows[0])==len(rows[1])==21)
    check('timestamped report',len(list(dest.glob('*/tls_full_report_*.txt')))==1)
    for scenario,needle in [('soon','EXPIRING SOON'),('expired','EXPIRED'),('self','SELF-SIGNED'),('legacy','DEPRECATED'),('null','WEAK CIPHER ACCEPTED'),('weak','RSA 1024-bit is below'),('missingchain','POSSIBLE MISSING INTERMEDIATE'),('missingocsp','MISSING OCSP'),('revoked','REVOKED'),('offline','NO TLS HANDSHAKE'),('timeout','INCOMPLETE COVERAGE')]:
        report,_,_=run(scenario);check('detect '+scenario,needle in report)
    report,_,_=run(host='wrong.test');check('mismatch','CN/SAN MISMATCH' in report)
    report,_,_=run(host='a.example.test');check('wildcard valid','CN/SAN MATCH' in report)
    report,_,_=run(host='a.b.example.test');check('wildcard depth rejected','CN/SAN MISMATCH' in report)
    report,_,_=run(host='unrelated.test');check('wildcard suffix rejected','CN/SAN MISMATCH' in report)
    report,dest,_=run(extra=('--no-history',));check('no history',not list(dest.glob('*/tls_full_report_*.txt')))
    hosts=t/'hosts.txt';hosts.write_text('# comment\nhttps://good.test/path\ngood.test:443\nhttp://plain.test\n')
    r=subprocess.run([str(ROOT/'tlswatch.sh'),'-l',str(hosts),'-o',str(t/'list'),'--ca-file',str(t/'ca.pem')],env=base,capture_output=True,text=True,timeout=60)
    check('list-only input',r.returncode==0)
    check('URL dedup and http skip','Endpoints    : 1' in next((t/'list').glob('*/tls_full_report.txt')).read_text())
    for args in [[],['--bogus'],['-d'],['-d','../evil'],['-d','host:0'],['-d','host:65536'],['-d','https://user:pass@host'],['-d','host','-t','0'],['-d','host','-w','-1'],['-l','/no/such/file']]:
        r=subprocess.run([str(ROOT/'tlswatch.sh'),*args],env=base,capture_output=True,timeout=20)
        check('reject '+repr(args),r.returncode==2)
    r=subprocess.run([str(ROOT/'tlswatch.sh'),'-h'],capture_output=True);check('help',r.returncode==0)
print(f'\nPASS {passed} / FAIL 0')
