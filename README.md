# SMART Health Card / "Vaccine Passport" Generator

A python script for issuing SMART Health Cards containing a record of
COVID-19 vaccination.

Obviously the resulting health card will only be valid if you are considered
to be a trusted issuer (i.e. probably a government, hospital, NGO, etc.) by
whatever person/app is scanning the code. And if that describes you, you
probably shouldn't be using sketchy scripts from github?  But you do you, I
guess.

This script was made primarily for my own interest/education and is not
intended to be used in any serious software products.  Also, please don't use
this for fraudulent purposes (not that it would be easy to do this).  The
correct way to obtain a vaccine passport is to *get vaccinated*.

Currently unfinished (it successfully generates codes/cards, but isn't
fully paramaterized or convenient to use yet).

# Dependencies:

Requires Python 3, plus the following packages: `qrcode`, `jwcrypto`,
and `pyyaml`.

# Usage:

To generate keys:

`python shc.py gen_keys`

This will generate `private_jwk.json`, containing the private signing key, and
`jwks.json` containing the public key and related information.  Make sure to
keep `private_jwk.json` safe and secret!

In order for people to actually be able to verify the SMART health cards that
you issue, you must make `jwks.json` publicly available on the internet at
`https://your.domain/some_arbitrary_path/.well-known/jwks.json`.  Note that
https is required.

Modify the example config file to include the correct name, vaccination dates, etc.  Set `issuer_url` based on where you placed `jwks.json` in the previous step (e.g. `https://your.domain/some_arbitrary_path` - note, do not include
`/` at the end).  You can also change which file the private key is loaded from and where to save the resulting qr code.

Finally, run:

`python shc.py config.yaml`

You can replace `config.yaml` with the path to some other config file, if desired.
