#!/usr/bin/env python
# -*- coding: utf-8 -*-
import web
import os
import random
import hashlib
import sys
import time

from certGenConstant import *

urls = (
    '/', 'CertGen',
    '/certGen', 'CertGen'
)

render = web.template.render('templates', base='layout')


app = web.application(urls, globals())
application = app.wsgifunc(web.httpserver.StaticMiddleware)

class CertGen(object):
    def GET(self):
        title = "Centificate Generator"
        return render.certGen(title, CC_LIST)
    def __makeOpensslCfg(self, fd, d, certParam):
        cert_list = ['[ ca ]', 'default_ca  = CA_default', '[ CA_default ]', 
                     'dir = %s/'%d, 'new_certs_dir = $dir/', 'database = $dir/index.txt',
                     'serial = $dir/serial', 'RANDFILE = $dir/.rand', 'x509_extensions = v3_ca',
                     'name_opt = ca_default', 'cert_opt = ca_default', 'default_days = '+certParam.ca_size,
                     'default_crl_days = 30', 'default_md = '+certParam.ca_md, 'policy = policy_match',
                     '[ policy_match ]', 'countryName = match', 'stateOrProvinceName = match',
                     'organizationName = match', 'organizationalUnitName = optional', 'commonName = supplied',
                     'emailAddress = optional', '[ policy_anything ]', 'countryName = optional', 
                     'stateOrProvinceName = optional', 'localityName = optional', 'organizationName = optional',
                     'organizationalUnitName = optional', 'commonName = supplied', 'emailAddress = optional',
                     '[ req ]', 'default_bits = 2048', 'default_md = sha1', 'default_keyfile = privkey.pem',
                     'distinguished_name = req_distinguished_name', 'x509_extensions = v3_ca', 'input_password = whatever',
                     'output_password = whatever', 'string_mask = nombstr', '[ req_distinguished_name ]',
                     'countryName = Country Name (2 letter code)', 'countryName_default = CN', 'countryName_min = 2',
                     'countryName_max = 2', 'stateOrProvinceName = State or Province Name (full name)',
                     'stateOrProvinceName_default = Beijing', 'localityName = Locality Name (eg, city)',
                     '0.organizationName = Organization Name (eg, company)', '0.organizationName_default = MyStartup Inc',
                     'organizationalUnitName = Organizational Unit Name (eg, section)', 
                     'organizationalUnitName_default = My Team', 'commonName = Common Name (eg, YOUR name)',
                     'commonName_default = My Name', 'commonName_max = 64', 'emailAddress = Email Address', 
                     'emailAddress = mymail@startup.com', 'emailAddress_max = 64',
                     '[ inter_ca ]', 'basicConstraints='+certParam.intermediate_ca_extensions_bc,
                     'subjectKeyIdentifier='+certParam.intermediate_ca_extensions_ski, 
                     'authorityKeyIdentifier='+certParam.intermediate_ca_extensions_aki,
                     'keyUsage = '+certParam.intermediate_ca_extensions_ku,
                     '[ ssl_server ]', 'basicConstraints = '+certParam.server_extensions_bc,
                     'keyUsage = '+certParam.server_extensions_ku, 'extendedKeyUsage = '+certParam.server_extensions_eku,
                     'subjectKeyIdentifier='+certParam.server_extensions_ski, 
                     'authorityKeyIdentifier='+certParam.server_extensions_aki,
                     'subjectAltName='+certParam.server_extensions_san,
                     '[ ssl_client ]', 'basicConstraints = '+certParam.client_extensions_bc,
                     'keyUsage = '+certParam.client_extensions_ku, 'extendedKeyUsage = '+certParam.client_extensions_eku,
                     'subjectKeyIdentifier = '+certParam.client_extensions_ski, 
                     'authorityKeyIdentifier = '+certParam.client_extensions_aki,
                     'subjectAltName = '+certParam.client_extensions_san, '[ v3_req ]',
                     'basicConstraints = CA:FALSE', 'keyUsage = nonRepudiation, digitalSignature, keyEncipherment',
                     '[ v3_ca ]', 'subjectKeyIdentifier = '+certParam.ca_extensions_ski,
                     'authorityKeyIdentifier = '+certParam.ca_extensions_aki, 
                     'basicConstraints = '+certParam.ca_extensions_bc,
                     'keyUsage = '+certParam.ca_extensions_ku]
        cert_list = [line+'\n' for line in cert_list]
        fd.writelines(cert_list)

    def POST(self):
        certParam = web.input()
        print certParam
        # Make a seed for certificate generation
        seed = hashlib.sha1(str(time.time())).hexdigest()
        tempdir = '/tmp/' + seed
        # mkdir for certificate generation
        try:
            os.mkdir(tempdir)
        except OSError as e:
            if e.errno == errno.EEXIST:
                return "File exists. Make certificate failed."
            raise web.seeother('/')
        # Make openssl.cnf
        try:
            fp = open(tempdir+"/openssl.cnf", 'w')
        except IOError as e:
            if e.errno == errno.EACCES:
                return "Permission denied. Make certificate failed."
            raise web.seeother('/')
        else:
            with fp:
                self.__makeOpensslCfg(fp, tempdir, certParam)
        os.system(r'touch %s/index.txt' % tempdir)
        # Generate CA
        if certParam.ca_private_key_passphrase == '':
            os.system(r'openssl genrsa -out %s/ca.key %s' % (tempdir, certParam.ca_size))
        else:
            os.system(r'openssl genrsa -des3 -out %s/ca.key -passout pass:"%s" %s' % 
                (tempdir, certParam.ca_private_key_passphrase, certParam.ca_size))
        os.system(r'openssl req -new -key %s/ca.key -out %s/ca.csr -days %s -config %s/openssl.cnf  -batch \
            -subj "/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s"' % (tempdir, tempdir, certParam.ca_valid_days or '365', 
                tempdir, certParam.ca_c or 'CN', certParam.ca_st or 'Beijing', certParam.ca_l or 'Beijing',
                certParam.ca_o or 'My Startup Inc',certParam.ca_ou or 'My Team', 
                certParam.ca_cn or 'My Certification Authority'))
        os.system(r'openssl req -x509 -in %s/ca.csr -key %s/ca.key -out %s/ca.crt -days %s -config %s/openssl.cnf -batch' %
            (tempdir, tempdir, tempdir, certParam.ca_valid_days or '365', tempdir))
        # Generate intermediate CA
        if certParam.ca_private_key_passphrase == '':
            os.system(r'openssl genrsa -out %s/interca.key %s' % (tempdir, certParam.intermediate_ca_size))
        else:
            os.system(r'openssl genrsa -des3 -out %s/interca.key -passout pass:"%s" %s' % 
                (tempdir, certParam.intermediate_ca_private_key_passphrase, certParam.intermediate_ca_size))
        os.system(r'openssl req -new -key %s/interca.key -out %s/interca.csr -days %s -config %s/openssl.cnf\
            -subj "/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s" -batch' % (tempdir, tempdir, certParam.intermediate_ca_valid_days,
                tempdir, certParam.intermediate_ca_c or 'CN', certParam.intermediate_ca_st or 'Beijing',
                certParam.intermediate_ca_l or 'Beijing', certParam.intermediate_ca_o or 'My Startup Inc',
                certParam.intermediate_ca_ou or 'My Team', certParam.intermediate_ca_cn or 'My Intermediate Certification Authority'))
        os.system(r'openssl ca -in %s/interca.csr -out %s/interca.crt -cert %s/ca.crt -config %s/openssl.cnf \
            -keyfile %s/ca.key  -extensions inter_ca  -passin pass:"%s" -create_serial -batch' % (tempdir,
                tempdir, tempdir, tempdir, tempdir, certParam.ca_private_key_passphrase))
        # Generate Server
        if certParam.ca_private_key_passphrase == '':
            os.system(r'openssl genrsa -out %s/server.key %s' % (tempdir, certParam.server_size))
        else:
            os.system(r'openssl genrsa -des3 -out %s/server.key -passout pass:"%s" %s' % 
                (tempdir, certParam.server_private_key_passphrase, certParam.server_size))
        os.system(r'openssl req -new -key %s/server.key -out %s/server.csr -days %s -config %s/openssl.cnf\
            -subj "/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s" -batch' % (tempdir, tempdir, certParam.server_valid_days,
                tempdir, certParam.server_c or 'CN', certParam.server_st or 'Beijing',
                certParam.server_l or 'Beijing', certParam.server_o or 'My Startup Inc',
                certParam.server_ou or 'My Team', certParam.server_cn or '*.mystartup.com'))
        os.system(r'openssl ca -in %s/server.csr -out %s/server.crt -cert %s/interca.crt -config %s/openssl.cnf \
            -keyfile %s/interca.key  -extensions ssl_server  -passin pass:"%s" -create_serial -batch' % (tempdir,
                tempdir, tempdir, tempdir, tempdir, certParam.intermediate_ca_private_key_passphrase))
        # Generate Client
        if certParam.ca_private_key_passphrase == '':
            os.system(r'openssl genrsa -out %s/client.key %s' % (tempdir, certParam.client_size))
        else:
            os.system(r'openssl genrsa -des3 -out %s/client.key -passout pass:"%s" %s' % 
                (tempdir, certParam.client_private_key_passphrase, certParam.client_size))
        os.system(r'openssl req -new -key %s/client.key -out %s/client.csr -days %s -config %s/openssl.cnf\
            -subj "/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s" -batch' % (tempdir, tempdir, certParam.client_valid_days,
                tempdir, certParam.client_c or 'CN', certParam.client_st or 'Beijing',
                certParam.client_l or 'Beijing', certParam.client_o or 'My Startup Inc',
                certParam.client_ou or 'My Team', certParam.client_cn or 'My Client Cert'))
        os.system(r'openssl ca -in %s/client.csr -out %s/client.crt -cert %s/interca.crt -config %s/openssl.cnf \
            -keyfile %s/interca.key  -extensions ssl_client  -passin pass:"%s" -create_serial -batch' % (tempdir,
                tempdir, tempdir, tempdir, tempdir, certParam.intermediate_ca_private_key_passphrase))
        # Combine server pem and client pem
        os.system(r'cat %s/server.key %s/server.crt > %s/server.pem' % (tempdir, tempdir, tempdir))
        os.system(r'cat %s/client.key %s/client.crt > %s/client.pem' % (tempdir, tempdir, tempdir))
        os.system(r'cat %s/ca.crt %s/interca.crt > %s/cachain.pem' % (tempdir, tempdir, tempdir))
        # Export P12 client cert
        os.system(r'openssl pkcs12 -export -in %s/client.pem -out %s/client.pfx \
            -passin pass:"%s" -passout pass:"%s"' % (tempdir, tempdir, certParam.client_private_key_passphrase,
                certParam.client_private_key_passphrase))
        reseed = hashlib.sha1(seed).hexdigest()
        certdir = '/tmp/' + reseed
        try:
            os.mkdir(certdir)
        except OSError as e:
            if e.errno == errno.EEXIST:
                return "File exists. Make certificate failed."
            raise web.seeother('/')
        os.system(r'cp %s/cachain.pem %s/' % (tempdir, certdir))
        os.system(r'cp %s/ca.key %s/' % (tempdir, certdir))
        os.system(r'cp %s/interca.key %s/' % (tempdir, certdir))
        os.system(r'cp %s/server.pem %s/' % (tempdir, certdir))
        os.system(r'cp %s/client.pem %s/' % (tempdir, certdir))
        os.system(r'cp %s/client.pfx %s/' % (tempdir, certdir))
        os.system(r'rm -rf %s' % tempdir)
        os.system(r'tar zcvf %s.tar.gz -C %s %s' % (certdir, '/tmp/', reseed))
        os.system(r'rm -rf %s' % certdir)

        c = None
        with open('%s.tar.gz'%certdir, 'rb') as f:
            web.header('Content-Type', 'application/octet-stream')
            web.header('Content-disposition', 'attachment; filename=certs.tar.gz')
            c = f.read()
        os.system(r'rm -rf %s.tar.gz' % certdir)
        return c

if __name__ == "__main__":
    app.run()