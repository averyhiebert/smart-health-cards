import json
import zlib

import qrcode

from jwcrypto import jwk, jws
from jwcrypto.common import json_encode


# Utils =============================================================
# (Mostly for compressing/decompressing the payload)


def deflate(string_val):
    ''' Modified from https://stackoverflow.com/questions/1089662/python-inflate-and-deflate-implementations.
    
    Take a str, compress and url-safe b64 encode it.'''
    zlibbed_str = zlib.compress(string_val.encode())
    compressed_string = zlibbed_str[2:-4] # omit zlib headers, per spec
    return compressed_string

def inflate( compressed ):
    ''' Take compressed bytes, convert to original str.'''
    return zlib.decompress(compressed, -15).decode("utf-8")


# Main token-creation functions =========================================

def get_FHIR_bundle(first_name="John",last_name="Doe",
        bday="2000-01-01"):
    ''' Generate the vaccination record itself. TODO Implement all the
    necessary passable parameters.'''

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

def token_to_qr(token):
    return "shc:/" + "".join([f"{(ord(c)-45):02d}" for c in token])


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
        json.dump(key_info,f)

    del key_info["d"] # Very Important! Don't make private key public.

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

    return token.serialize(compact=True) # b64 string of the token.

def load_and_verify_jws_token(token,
        key_file="example_jwks.json"):
    ''' Read & validate a serialized token.
    
    Throws an error if invalid (assuming signed by the example issuer),
    otherwise returns the (decompressed) payload (in dict form).
    
    Lots of hacks in this, since I just used it for testing.  This is not
    good as a general-purpose smart-health-card file reader.'''

    # Load public key from file.
    # TODO Fetch from specified url?
    #  (This would require extracting the package without verifying, which this
    #  jws library does not allow...)
    with open(key_file,"r") as f:
        key_data = json.load(f)

    # TODO Check correct key, not just the first one.
    public_key = jwk.JWK(**key_data["keys"][0])

    jws_token = jws.JWS()
    jws_token.deserialize(token)
    jws_token.verify(public_key)

    return json.loads(inflate(jws_token.payload)) # inflate = uncompress

# Main ===================================================================

def gen_smart_health_card(write_file=False,**kwargs):
    ''' Eventually will be the function that actually takes a bunch of
    configuration data and creates the QR code.'''
    # Create the data
    FHIR = get_FHIR_bundle()
    vc = get_VC_bundle(FHIR)
    #minified = json.dumps(vc,separators=(",",":"))
    payload = deflate(json.dumps(vc,separators=(",",":")))
    jws_token = get_JWS(payload) # Note: is a str, not bytes

    # Write smart health file
    if write_file:
        final_data = json.dumps({"verifiableCredential": [jws_token]})
        with open("test.smart-health-card","w") as f:
            f.write(final_data)
        
    # Generate QR code.
    img = qrcode.make(token_to_qr(jws_token))
    img.save("smart-health-card.png")

# Testing ============================

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




if __name__=="__main__":
    gen_smart_health_card(issuer="https://noctes.mathematicae.ca/vaccination")
    pass

