import json
import zlib
#import base64

import qrcode

from jwcrypto import jwk, jws
from jwcrypto.common import json_encode


# Utils =============================================================
# (Mostly for deflating and inflating the payload)

def test_qr():
    img = qrcode.make("Here is some text")
    print(type(img))
    img.save("test.png")

def deflate(string_val):
    ''' Modified from https://stackoverflow.com/questions/1089662/python-inflate-and-deflate-implementations.
    
    Take a str, compress and url-safe b64 encode it.'''
    zlibbed_str = zlib.compress(string_val.encode())
    compressed_string = zlibbed_str[2:-4] # omit zlib headers, per spec
    #return base64.urlsafe_b64encode(compressed_string)
    return compressed_string

def add_padding(s):
    ''' Add necessary padding for b64 encoding. '''
    missing_padding = len(s) % 3 # Must pad to a multiple-of-3 bytes
    if missing_padding:
        s = s + b'='*(3-missing_padding)
    return s

def from_b64(s):
    return base64.urlsafe_b64decode(add_padding(s))

#def to_b64(s):
    #''' Given a string, returns bytes '''
    #return base64.urlsafe_b64encode(s.encode("utf-8"))

def inflate( compressed ):
    ''' Take url-safe b64encoded bytes, convert to original str.'''
    #decoded_data = base64.b64decode( b64string )
    return zlib.decompress(compressed, -15).decode("utf-8")

# Main token-creation functions =========================================

def get_FHIR_bundle(first_name="John",last_name="Doe",
        bday="2000-01-01"):
    ''' Generate the vaccination record (no signing etc. yet). '''

    patient = {
      'fullUrl': 'resource:0', 
      'resource': {
        'resourceType': 'Patient', 
        'name': [{'family': 'Doe', 'given': ['John']}], 
        'birthDate': '2000-01-20'}
    }

    # The GOOD one:
    imm1 = { 'fullUrl': 'resource:1', 
      'resource': {
            'resourceType': 'Immunization', 
            'status': 'completed', 
            'vaccineCode': {'coding': [{'system': 'http://hl7.org/fhir/sid/cvx', 'code': '207'}]}, 
            'patient': {'reference': 'resource:0'},
            'occurrenceDateTime': '2021-01-01', 
            'performer': [{'actor': 
                {'display': 'Dr. Nick Riviera'}}],
            'lotNumber': '00000001'
      }
    }

    '''
    imm1 = {
        "fullUrl":"resource:1",
        "resource":{
            "resourceType":"Immunization",
            "status":"completed",
            "vaccineCode":{
                "coding":[{"system":"http://hl7.org/fhir/sid/cvx","code":207}]
            },
            "patient":{"reference":"resource:0"},
            "occurrenceDateTime:":"2021-01-01",
            "performer":[{"actor":{"display":"Some Hospital"}}],
            "lotNumber":"0000001"
        }
    }
    '''
    imm2 = {
      'fullUrl': 'resource:2', 
      'resource': {
        'resourceType': 'Immunization',
        'status': 'completed',
        'vaccineCode': {'coding': [{'system': 'http://hl7.org/fhir/sid/cvx', 'code': '207'}]}, 
        'patient': {'reference': 'resource:0'}, 
        'occurrenceDateTime': '2021-01-29', 
        'performer': [{'actor': 
            {'display': 'Some guy in an alley, idk'}}], 
            'lotNumber': '42069'
      }
    }

    FHIR = {
        "resourceType":"Bundle",
        "type":"collection",
        "entry": [patient,imm1,imm2]
    }

    return FHIR

def get_VC_bundle(FHIR,
        issuer_url="https://noctes.mathematicae.ca/vaccination"):
    ''' Given FHIR bundle, generate VC bundle. '''

    vc = {
        "iss":issuer_url,
        "nbf":0, # "Not before" (in seconds since epoch, TODO set 2 weeks after 2nd vaccination)
        "vc": {
            "type":[
                "https://smarthealth.cards#health-card",
                "https://smarthealth.cards#immunization",
                "https://smarthealth.cards#covid-19",
            ],
            "credentialSubject":{
                "fhirVersion":"4.0.1",
                "fhirBundle":FHIR
            }
        }
    }

    return vc


# Crypto stuff ======================================================

def gen_key():
    ''' Generates public/private key pair.  Writes two files:

      "jwks.json": contains only public info, in the format required for SMART 
                   Health Card (i.e. including "kid", and with a field "keys"
                   containing the jwk object)

      "private_jwk.json": jwk file for private key.
    '''
    key = jwk.JWK.generate(**{"kty":"EC","crv":"P-256","alg":"ES256",
        "use":"sig"})
    key_info = json.loads(key.export(private_key=True))
    key_info["kid"] = key.thumbprint()

    with open("private_jwk.json","w") as f:
        #f.write(key.export(private_key=False))
        json.dump(key_info,f)

    del key_info["d"] # Very Important !!!!

    with open("jwks.json","w") as f:
        obj = {"keys":[key_info]}
        json.dump(obj,f)


def get_JWS(payload,key_file="private_jwk.json"):
    ''' Given a payload (already compressed/encoded) and a json object
    representing the private key, encode into a serialized jws token.'''

    with open(key_file,"r") as f:
        key_data=json.load(f)
    private_key = jwk.JWK(**key_data)

    header = {"kid":private_key.thumbprint(),"zip":"DEF", "alg":"ES256"}

    token = jws.JWS(payload)
    token.add_signature(private_key, alg="ES256", protected=json_encode(header))


    return token.serialize(compact=True) # Returns a string of the token, I guess?

def load_and_verify_jws_token(token_file="example-00-d-jws.txt",
        key_file="example_jwks.json"):
    ''' Load the token file (data that would be contained in QR code).
    
    Throws an error if invalid (assuming signed by the example issuer),
    otherwise returns the (decompressed) payload (in dict form).'''
    with open(key_file,"r") as f:
        key_data = json.load(f)

    # Get public key from example token
    public_key = jwk.JWK(**key_data["keys"][0])


    # Deserialize example token
    with open(token_file,"r") as f:
        token_data = f.read()

    jws_token = jws.JWS()
    jws_token.deserialize(token_data)
    jws_token.verify(public_key)

    return json.loads(inflate(jws_token.payload))

# Main ===================================================================

def gen_smart_health_card(**kwargs):
    ''' Eventually will be the function that actually takes a bunch of
    configuration data and creates the QR code.'''
    FHIR = get_FHIR_bundle()
    vc = get_VC_bundle(FHIR)

    minified = json.dumps(vc,separators=(",",":")) # If package doesn't automatically do this.  I think it does, though?
    payload = deflate(minified)

    jws_token = get_JWS(payload) # Note: is a str


    final_data = json.dumps({"verifiableCredential": [jws_token]})

    # Write smart health file
    with open("test.smart-health-card","w") as f:
        f.write(final_data)
        
    # Generate QR code.
    img = qrcode.make(token_to_qr(jws_token))
    img.save("test.png")

# Testing ============================

def read_headers_from_compact(fname):
    with open(fname,"rb") as f:
        data = f.read()
    print(from_b64(data))
    print(inflate(from_b64(data)))

def check_health_card(fname, key_fname):
    ''' Check that the final health card data is correct/readable/verifiable '''
    with open(fname,"r") as f:
        data = json.load(f)
    token_data = data["verifiableCredential"][0]

    with open(key_fname,"r") as f:
        key_data = json.load(f)

    # Get public key from example token
    public_key = jwk.JWK(**key_data["keys"][0])

    jws_token = jws.JWS()
    jws_token.deserialize(token_data)
    jws_token.verify(public_key)

    text = json.loads(inflate(jws_token.payload))
    print(text)
    return token_data

def token_to_qr(token):
    return "shc:/" + "".join([f"{(ord(c)-45):02d}" for c in token])



if __name__=="__main__":
    gen_smart_health_card(issuer="https://noctes.mathematicae.ca/vaccination")

    #check_health_card(fname="example-00-e-file.smart-health-card",
    #    key_fname="example_jwks.json")
    #check_health_card(fname="test.smart-health-card",
    #    key_fname="jwks.json")

    pass

