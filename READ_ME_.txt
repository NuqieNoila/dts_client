Once timestamp authority has sent the response following a timestamp request, the following steps are taken to verify the timestamp response file(.tsr):

# Input
1. Timestamp response file(.tsr)
2. Timestamp request file(.tsq)
3. Timestamp authority (TSA) certificate
4. CA certificate (CA of TSA)

# Parse
1. Decode the response using TimeStampResp format
2. Decode the binary string written in eContent using TSTInfo format
3. Decode the request using TimeStampReq format

# Verify
1. Check the status of TimeStampResp

2. Check the fields in decoded TSTInfo
	a) Must have a policy, if TimeStampReq stated reqPolicy, it must be equal.
	b) messageImprint in tsr is equal to the one in tsq.
	c) If nonce is available, the value must be equal to the one in tsq.

3. Check there is only one SignerInfo entry in signerInfos.

4. Check the signedAttrs (signedAttributes)
	a) For attrType=id-contentType, entry in attrValues is the encoded eContentType
	b) For attrType=id-signingTime, entry in attrValues is equal to genTime in TSTInfo
	c) For attrType=message-digest, entry in attrValues is equal to the hash of eContent using hash algorithm stated in digestAlgorithm
	d) For attrType=id-aa-signingCertificate, the hash of TSA cert is equal to certHash of SigningCertificate

5. Check details regarding the TSA certificate
	a) Check the certificate trust chain using CA certificate
	b) Make sure genTime is between certificate period of validity
	c) Check the extendedKeyUsage field
	d) Check whether the TSA certificate is in CRL of CA --TODO

6. Check the signature
	a) The input of the verification of signature:
		- TSA cert (public key)
		- Hash of complete DER encoding of signedAttrs
		- Signature value written in SignerInfo


Once all the verification steps are done, we will trust the TimeStampToken given by TSA server.
