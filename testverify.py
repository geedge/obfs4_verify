# -*- coding:utf-8 -*-
import base64
import binascii
import socket
import elligator
from os import urandom
import hmac
import hashlib
import string
import time
import random

#const

iatNone = 0
iatEnabled=1
iatParanoid=2

certSuffix      = "=="
certLength      = 20+32
maxIATDelay     = 100
consumeReadSize = (1500 - (40 + 12)) * 16

packetOverhead          = 2 + 1
seedLength              = 16+8
seedPacketPayloadLength = seedLength
maxHandshakeLength      = 8192
inlineSeedFrameLength = 2+ 16+2+1 + seedPacketPayloadLength

clientMinHandshakeLength = 32 + 16 + 16
clientMinPadLength = (32+32+32 + inlineSeedFrameLength) -clientMinHandshakeLength
clientMaxPadLength       = maxHandshakeLength - clientMinHandshakeLength
	
serverMinPadLength = 0
serverMinHandshakeLength = 32 + 32 + 32
serverMaxPadLength = maxHandshakeLength - (serverMinHandshakeLength + inlineSeedFrameLength)

NodeIDLength=20	
PublicKeyLength=32
PrivateKeyLength=32
RepresentativeLength = 32
markLength = 32 / 2
macLength  = 32 / 2
AuthLength = 32
#############

class obfs4ServerCert:
    def __init__(self):
        self.raw = bytearray()

class Keypair:
	def __init__(self):
		self.public=bytearray(PublicKeyLength)
		self.private=bytearray(PrivateKeyLength)
		self.representative=bytearray(RepresentativeLength)

class clientHandshake:
	def __init__(self):
		self.keypair=Keypair()
		self.nodeID=bytearray(NodeIDLength)
		self.serverIdentity=bytearray(PublicKeyLength)
		self.epochHour=bytearray()
		self.padLen=0
		self.mac=bytearray()
		self.serverRepresentative=bytearray(RepresentativeLength)
		self.serverAuth=bytearray(AuthLength)
		self.serverMark=bytearray()

def serverCertFromString(encoded):
	try:
		decoded=base64.standard_b64decode(encoded+certSuffix)
	except:
		print "failed to decode cert"
		exit()
	else:
		if len(decoded) != certLength:
			print("cert length %d is invalid", len(decoded))
			exit()
		
		servercert=obfs4ServerCert()
		#print binascii.hexlify(decoded)
		servercert.raw=bytearray(decoded)
		return servercert
	#for s in decoded:
	#	string_int1 = int(binascii.hexlify(s),16)
	#	print string_int1

def NewNodeID(raw):
	if len(raw)!=NodeIDLength:
		print("NodeIDLengthError:%d",len(raw))
		exit()
	nodeID=bytearray(raw)
	return nodeID

def NewPublicKey(raw):
	if len(raw) != PublicKeyLength:
		print("PublicKeyLengthError:%d",len(raw))
		exit()
	pubKey=bytearray(raw)
	return pubKey

def unpack(cert):
	if len(cert.raw)!=certLength:
		print("cert length %d is invalid", len(cert.raw))
		exit()
	nodeID=NewNodeID(cert.raw[:20])
	pubKey=NewPublicKey(cert.raw[20:])
	return nodeID,pubKey

def NewKeypair():
	try:
		while True:
			private = urandom(32)
    		(valid, public, representative) = elligator.scalarbasemult(private)
    		if valid:
				break
		keypair=Keypair()
		keypair.private=bytearray(private)
		keypair.public=bytearray(public)
		keypair.representative=bytearray(representative)
		return keypair
	except:
		print "failed to generate keypair"
		exit() 

def newClientHandshake(nodeID,serveridentity,sessionkey):
	hs=clientHandshake()
	hs.keypair=sessionkey
	hs.nodeID=nodeID
	hs.serverIdentity=serveridentity
	hs.padLen=random.choice(range(clientMinPadLength,clientMaxPadLength))
	hs.mac=bytearray.fromhex(hmac.new(serveridentity+nodeID,sessionkey.representative,digestmod=hashlib.sha256).hexdigest()[:32])
	return hs

def findMarkMac(mark, buf, startPos, maxPos, fromTail):
	if len(mark)!=markLength:
		print "BUG: Invalid mark length"
		exit()
	endPos=len(buf)
	if startPos>len(buf):
		return -1
	if endPos>maxPos:
		endPos=maxPos
	if endPos-startPos<markLength+macLength:
		return -1
	if fromTail:
		pos=endPos-(markLength+macLength)
		if mark!=buf[pos:pos+markLength]:
			return -1
		return
	pos=buf[startPos:endPos].find(mark)
	if pos == -1:
		return -1
	if startPos+pos+markLength+macLength>endPos:
		return -1

	pos += startPos
	return pos

def Makepad(padlen):
	pad=bytearray(urandom(padlen))
	return pad

def getEpochHour():
	return int(time.time())/3600
def generatehandshake(hs):
	'''
	// The client handshake is X | P_C | M_C | MAC(X | P_C | M_C | E) where:
	//  * X is the client's ephemeral Curve25519 public key representative.
	//  * P_C is [clientMinPadLength,clientMaxPadLength] bytes of random padding.
	//  * M_C is HMAC-SHA256-128(serverIdentity | NodeID, X)
	//  * MAC is HMAC-SHA256-128(serverIdentity | NodeID, X .... E)
	//  * E is the string representation of the number of hours since the UNIX
	//    epoch.
	'''
	pad=Makepad(hs.padLen)
	buf=hs.keypair.representative+pad+hs.mac
	hs.epochHour=bytearray(str(getEpochHour()))
	macc=bytearray.fromhex(hmac.new(hs.serverIdentity+hs.nodeID,buf+hs.epochHour,digestmod=hashlib.sha256).hexdigest()[:32])
	return buf+macc

def parseServerHandshake(hs,resp):
	if serverMinHandshakeLength > len(resp):
		print "serverhserr"
		return False
	hs.serverRepresentative=resp[0:RepresentativeLength]
	hs.serverAuth=resp[RepresentativeLength:]
	hs.serverMark=bytearray.fromhex(hmac.new(hs.serverIdentity+hs.nodeID,hs.serverRepresentative,digestmod=hashlib.sha256).hexdigest()[:32])
	#Attempt to find the mark + MAC
	pos=findMarkMac(hs.serverMark,resp,RepresentativeLength+AuthLength+serverMinPadLength,maxHandshakeLength,False)
	if pos == -1:
		if len(resp)>=maxHandshakeLength:
			print "invalidserverhs"
			return False
		print "marknotfond"
		return False
	#Validate the MAC
	macCmp=bytearray.fromhex(hmac.new(hs.serverIdentity+hs.nodeID,resp[:pos+markLength]+hs.epochHour,digestmod=hashlib.sha256).hexdigest()[:32])
	macRx=resp[pos+markLength:pos+markLength+macLength]
	if macCmp!=macRx:
		print "invalidmac"
		return False

	return True
		

def cHandshake(s,nodeID,publickey,sessionkey):
	hs=newClientHandshake(nodeID,publickey,sessionkey)
	blob=generatehandshake(hs)
	s.send(blob)
	recbuf=bytearray(maxHandshakeLength)
	while True:
    	a = s.recv(1024)
    	if not len(a):
			break
    	recbuf+=a
	return parseServerHandshake(hs,recbuf)




def verify(ptname,certstr,address):
	cert=serverCertFromString(certstr)
	nodeID, publicKey = unpack(cert)
	#print binascii.hexlify(nodeID)
	sessionKey=NewKeypair()
	try:
		li=address.split(':')
		ip=li[0]
		port=li[1]
	except:
		print 'address format error'
		exit()
	try:
		s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((ip,port))
	except:
		print 'connect error'
		exit()
	try:
		cHandshake(s,nodeID,publicKey,sessionKey)
	except:
		print 'client hs error'
		exit()
		

	return 1

if __name__ == '__main__':
	ptName = "obfs4"
	certStr = "iJ8il3a2gVXuNdZoaPwQ0QgdOJyBAi4fcY642f6sTErVNZ14Ax7c9w9qa36mUXQhbm9vOg"
	#certStr = "M6tiPcFv8YK2jE8pYZb9AKMMHHag4OrhHFWmOXHR+J9s8Ty9X9V+Bn0emEZmfnqhdtHkdA"
	address = "185.185.251.132:443"
	#address = "45.32.201.89:51433"
	result = verify(ptName, certStr, address)
	print result