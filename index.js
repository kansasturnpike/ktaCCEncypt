import {pidCrypt, pidCryptUtil} from './pidcript/index.js'
// import pidCrypt from 'pidcrypt'
// import pidCryptUtil from 'pidcrypt/pidcrypt_util.js'
// import 'pidcrypt/rsa.js'
// import 'pidcrypt/asn1.js'

const public_key =
	'-----BEGIN RSA PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0QmKXJTE0G7aO2j32Pui\n\
xgiNDyAoprnLbihUxl0mnPQHoxFNeiHB0eUEjcRvShTYbzFOYa78mTpYgx0ztvwo\n\
gAwBWEmn2QMKuqXOEOdb9HeOl63MWqAaEK1yNheWj5fDZNXnsSsya4lL7JTG1dCd\n\
uek6g4uUcrgXBEXifOXyT5Z7Gb202nPhclOXMwZIstGpygkXEpN+n4JTkEA9b1Fk\n\
37aiLes4H5AaahgqbOM7ytjOzaWthwJDtVMPvK0ZYDi1JWAOXxjXTRA4OKeXC8j3\n\
29u09v5BZ5LlTAWI0fNetRy9vIVG1Em545IHSzgrk0h7I09FV1N4Fv9PkCHTdlde\n\
3wIDAQAB\n\
-----END RSA PUBLIC KEY-----'

function isNumber(e) {
	return !isNaN(parseFloat(e)) && isFinite(e)
}
function IETrim(e) {
	return e.replace(/^\s+|\s+$/g, '')
}
function certParser(e) {
	var t = e.split('\n')
	var n = false
	var r = false
	var i = false
	var s = ''
	var o = {}
	o.info = ''
	o.salt = ''
	o.iv
	o.b64 = ''
	o.aes = false
	o.mode = ''
	o.bits = 0
	for (var u = 0; u < t.length; u++) {
		s = t[u].substr(0, 9)
		if (u == 1 && s != 'Proc-Type' && s.indexOf('M') == 0) r = true
		switch (s) {
			case '-----BEGI':
				n = true
				break
			case 'Proc-Type':
				if (n) o.info = t[u]
				break
			case 'DEK-Info:':
				if (n) {
					var a = t[u].split(',')
					var f = a[0].split(': ')
					var l = f[1].split('-')
					o.aes = l[0] == 'AES' ? true : false
					o.mode = l[2]
					o.bits = parseInt(l[1])
					o.salt = a[1].substr(0, 16)
					o.iv = a[1]
				}
				break
			case '':
				if (n) r = true
				break
			case '-----END ':
				if (n) {
					r = false
					n = false
				}
				break
			default:
				if (n && r) o.b64 += pidCryptUtil.stripLineFeeds(t[u])
		}
	}
	return o
}

function buildXML(e, t, n) {
	e = IETrim(e)
	t = IETrim(t)
	n = IETrim(n)
	if (e == '') {
		return 'Account Number blank'
	}
	if (t == '') {
		return 'Expiration Date blank'
	}
	if (n == '') {
		return 'CVV blank'
	}
	if (!isNumber(e)) {
		return 'Account Number non-Numeric'
	}

	let i = {}
	i = certParser(public_key)
	if (i.b64) {
		let s = pidCryptUtil.decodeBase64(i.b64)
		let o = new pidCrypt.RSA()
		let u = pidCrypt.ASN1.decode(pidCryptUtil.toByteArray(s))
		let a = u.toHexTree()
		o.setPublicKeyFromASN(a)
		let f
		let l = 'TEMPUSRSA2014'
		let c = 'RSA'
		let h = 'FALSE'
		let p = 'KEY'
		let d = pidCryptUtil.stripLineFeeds(pidCryptUtil.fragment(pidCryptUtil.encodeBase64(pidCryptUtil.convertFromHex(o.encryptRaw(e))), 64))
		let v = pidCryptUtil.stripLineFeeds(pidCryptUtil.fragment(pidCryptUtil.encodeBase64(pidCryptUtil.convertFromHex(o.encryptRaw(t))), 64))
		let m = pidCryptUtil.stripLineFeeds(pidCryptUtil.fragment(pidCryptUtil.encodeBase64(pidCryptUtil.convertFromHex(o.encryptRaw(n))), 64))
		f = '<CARDEVENTPARAMS>'
		f = f + '<ENCDVCDEVICETYPE>' + '6' + '</ENCDVCDEVICETYPE>'
		f = f + '<ENCDVCKSN>' + l + '</ENCDVCKSN>'
		f = f + '<ENCDVCENCTYPE>' + c + '</ENCDVCENCTYPE>'
		f = f + '<ENCDVCENCOAEPPADDED>' + h + '</ENCDVCENCOAEPPADDED>'
		f = f + '<ENCDVCCARDDATASOURCE>' + p + '</ENCDVCCARDDATASOURCE>'
		f = f + '<ENCDVCENCRYPTEDPAN>' + d + '</ENCDVCENCRYPTEDPAN>'
		f = f + '<ENCDVCENCRYPTEDEXP>' + v + '</ENCDVCENCRYPTEDEXP>'
		f = f + '<ENCDVCENCRYPTEDCVV>' + m + '</ENCDVCENCRYPTEDCVV>'
		f = f + '</CARDEVENTPARAMS>'
		return f
	} else {
		return 'No Public Key Found'
	}
}

export default buildXML
