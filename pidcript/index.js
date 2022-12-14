/*
The following sections are copied from the pidCrypt Javascript crypto library and are subject to their own GPL license. 
See https://www.pidder.de/pidcrypt for more information

Begin PidCrypt.js
**/
/*Copyright (c) 2009 pidder <www.pidder.com>*/
export function pidCrypt() {
	function a(b) {
		if (!b) {
			b = 8
		}
		var c = new Array(b)
		var e = []
		for (var d = 0; d < 256; d++) {
			e[d] = d
		}
		for (d = 0; d < c.length; d++) {
			c[d] = e[Math.floor(Math.random() * e.length)]
		}
		return c
	}
	this.setDefaults = function () {
		this.params.nBits = 256
		this.params.salt = a(8)
		this.params.salt = pidCryptUtil.byteArray2String(this.params.salt)
		this.params.salt = pidCryptUtil.convertToHex(this.params.salt)
		this.params.blockSize = 16
		this.params.UTF8 = true
		this.params.A0_PAD = true
	}
	this.debug = true
	this.params = {}
	this.params.dataIn = ''
	this.params.dataOut = ''
	this.params.decryptIn = ''
	this.params.decryptOut = ''
	this.params.encryptIn = ''
	this.params.encryptOut = ''
	this.params.key = ''
	this.params.iv = ''
	this.params.clear = true
	this.setDefaults()
	this.errors = ''
	this.warnings = ''
	this.infos = ''
	this.debugMsg = ''
	this.setParams = function (c) {
		if (!c) {
			c = {}
		}
		for (var b in c) {
			this.params[b] = c[b]
		}
	}
	this.getParams = function () {
		return this.params
	}
	this.getParam = function (b) {
		return this.params[b] || ''
	}
	this.clearParams = function () {
		this.params = {}
	}
	this.getNBits = function () {
		return this.params.nBits
	}
	this.getOutput = function () {
		return this.params.dataOut
	}
	this.setError = function (b) {
		this.error = b
	}
	this.appendError = function (b) {
		this.errors += b
		return ''
	}
	this.getErrors = function () {
		return this.errors
	}
	this.isError = function () {
		if (this.errors.length > 0) {
			return true
		}
		return false
	}
	this.appendInfo = function (b) {
		this.infos += b
		return ''
	}
	this.getInfos = function () {
		return this.infos
	}
	this.setDebug = function (b) {
		this.debug = b
	}
	this.appendDebug = function (b) {
		this.debugMsg += b
		return ''
	}
	this.isDebug = function () {
		return this.debug
	}
	this.getAllMessages = function (c) {
		var g = {lf: '\n', clr_mes: false, verbose: 15}
		if (!c) {
			c = g
		}
		for (var h in g) {
			if (typeof c[h] == 'undefined') {
				c[h] = g[h]
			}
		}
		var b = ''
		var e = ''
		for (var f in this.params) {
			switch (f) {
				case 'encryptOut':
					e = pidCryptUtil.toByteArray(this.params[f].toString())
					e = pidCryptUtil.fragment(e.join(), 64, c.lf)
					break
				case 'key':
				case 'iv':
					e = pidCryptUtil.formatHex(this.params[f], 48)
					break
				default:
					e = pidCryptUtil.fragment(this.params[f].toString(), 64, c.lf)
			}
			b += '<p><b>' + f + '</b>:<pre>' + e + '</pre></p>'
		}
		if (this.debug) {
			b += 'debug: ' + this.debug + c.lf
		}
		if (this.errors.length > 0 && (c.verbose & 1) == 1) {
			b += 'Errors:' + c.lf + this.errors + c.lf
		}
		if (this.warnings.length > 0 && (c.verbose & 2) == 2) {
			b += 'Warnings:' + c.lf + this.warnings + c.lf
		}
		if (this.infos.length > 0 && (c.verbose & 4) == 4) {
			b += 'Infos:' + c.lf + this.infos + c.lf
		}
		if (this.debug && (c.verbose & 8) == 8) {
			b += 'Debug messages:' + c.lf + this.debugMsg + c.lf
		}
		if (c.clr_mes) {
			this.errors = this.infos = this.warnings = this.debug = ''
		}
		return b
	}
	this.getRandomBytes = function (b) {
		return a(b)
	}
}
/**
End PidCrypt.js
Begin PidCrypt_Util.js
**/
export const pidCryptUtil = {}
pidCryptUtil.encodeBase64 = function (n, p) {
	if (!n) {
		n = ''
	}
	var g = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
	p = typeof p == 'undefined' ? false : p
	var f,
		b,
		a,
		r,
		o,
		k,
		j,
		h,
		i = [],
		d = '',
		m,
		q,
		l
	q = p ? pidCryptUtil.encodeUTF8(n) : n
	m = q.length % 3
	if (m > 0) {
		while (m++ < 3) {
			d += '='
			q += '\0'
		}
	}
	for (m = 0; m < q.length; m += 3) {
		f = q.charCodeAt(m)
		b = q.charCodeAt(m + 1)
		a = q.charCodeAt(m + 2)
		r = (f << 16) | (b << 8) | a
		o = (r >> 18) & 63
		k = (r >> 12) & 63
		j = (r >> 6) & 63
		h = r & 63
		i[m / 3] = g.charAt(o) + g.charAt(k) + g.charAt(j) + g.charAt(h)
	}
	l = i.join('')
	l = l.slice(0, l.length - d.length) + d
	return l
}
pidCryptUtil.decodeBase64 = function (n, e) {
	if (!n) {
		n = ''
	}
	var g = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
	e = typeof e == 'undefined' ? false : e
	var f,
		b,
		a,
		o,
		k,
		i,
		h,
		q,
		j = [],
		p,
		m
	m = e ? pidCryptUtil.decodeUTF8(n) : n
	for (var l = 0; l < m.length; l += 4) {
		o = g.indexOf(m.charAt(l))
		k = g.indexOf(m.charAt(l + 1))
		i = g.indexOf(m.charAt(l + 2))
		h = g.indexOf(m.charAt(l + 3))
		q = (o << 18) | (k << 12) | (i << 6) | h
		f = (q >>> 16) & 255
		b = (q >>> 8) & 255
		a = q & 255
		j[l / 4] = String.fromCharCode(f, b, a)
		if (h == 64) {
			j[l / 4] = String.fromCharCode(f, b)
		}
		if (i == 64) {
			j[l / 4] = String.fromCharCode(f)
		}
	}
	p = j.join('')
	p = e ? pidCryptUtil.decodeUTF8(p) : p
	return p
}
pidCryptUtil.encodeUTF8 = function (a) {
	if (!a) {
		a = ''
	}
	a = a.replace(/[\u0080-\u07ff]/g, function (d) {
		var b = d.charCodeAt(0)
		return String.fromCharCode(192 | (b >> 6), 128 | (b & 63))
	})
	a = a.replace(/[\u0800-\uffff]/g, function (d) {
		var b = d.charCodeAt(0)
		return String.fromCharCode(224 | (b >> 12), 128 | ((b >> 6) & 63), 128 | (b & 63))
	})
	return a
}
pidCryptUtil.decodeUTF8 = function (a) {
	if (!a) {
		a = ''
	}
	a = a.replace(/[\u00c0-\u00df][\u0080-\u00bf]/g, function (d) {
		var b = ((d.charCodeAt(0) & 31) << 6) | (d.charCodeAt(1) & 63)
		return String.fromCharCode(b)
	})
	a = a.replace(/[\u00e0-\u00ef][\u0080-\u00bf][\u0080-\u00bf]/g, function (d) {
		var b = ((d.charCodeAt(0) & 15) << 12) | ((d.charCodeAt(1) & 63) << 6) | (d.charCodeAt(2) & 63)
		return String.fromCharCode(b)
	})
	return a
}
pidCryptUtil.convertToHex = function (d) {
	if (!d) {
		d = ''
	}
	var c = ''
	var a = ''
	for (var b = 0; b < d.length; b++) {
		a = d.charCodeAt(b).toString(16)
		c += a.length == 1 ? '0' + a : a
	}
	return c
}
pidCryptUtil.convertFromHex = function (c) {
	if (!c) {
		c = ''
	}
	var b = ''
	for (var a = 0; a < c.length; a += 2) {
		b += String.fromCharCode(parseInt(c.substring(a, a + 2), 16))
	}
	return b
}
pidCryptUtil.stripLineFeeds = function (b) {
	if (!b) {
		b = ''
	}
	var a = ''
	a = b.replace(/\n/g, '')
	a = a.replace(/\r/g, '')
	return a
}
pidCryptUtil.toByteArray = function (b) {
	if (!b) {
		b = ''
	}
	var c = []
	for (var a = 0; a < b.length; a++) {
		c[a] = b.charCodeAt(a)
	}
	return c
}
pidCryptUtil.fragment = function (e, d, a) {
	if (!e) {
		e = ''
	}
	if (!d || d >= e.length) {
		return e
	}
	if (!a) {
		a = '\n'
	}
	var c = ''
	for (var b = 0; b < e.length; b += d) {
		c += e.substr(b, d) + a
	}
	return c
}
pidCryptUtil.formatHex = function (f, e) {
	if (!f) {
		f = ''
	}
	if (!e) {
		e = 45
	}
	var a = ''
	var b = 0
	var d = f.toLowerCase()
	for (var c = 0; c < d.length; c += 2) {
		a += d.substr(c, 2) + ':'
	}
	d = this.fragment(a, e)
	return d
}
pidCryptUtil.byteArray2String = function (a) {
	var d = ''
	for (var c = 0; c < a.length; c++) {
		d += String.fromCharCode(a[c])
	}
	return d
}
/**
End PidCrypt_Util.js
Begin asn1.js
**/
export function Stream(a, b) {
	if (a instanceof Stream) {
		this.enc = a.enc
		this.pos = a.pos
	} else {
		this.enc = a
		this.pos = b
	}
}
Stream.prototype.parseStringHex = function (e, a) {
	if (typeof a == 'undefined') {
		a = this.enc.length
	}
	var d = ''
	for (var b = e; b < a; ++b) {
		var c = this.get(b)
		d += this.hexDigits.charAt(c >> 4) + this.hexDigits.charAt(c & 15)
	}
	return d
}
Stream.prototype.get = function (a) {
	if (a == undefined) {
		a = this.pos++
	}
	if (a >= this.enc.length) {
		throw 'Requesting byte offset ' + a + ' on a stream of length ' + this.enc.length
	}
	return this.enc[a]
}
Stream.prototype.hexDigits = '0123456789ABCDEF'
Stream.prototype.hexDump = function (e, a) {
	var d = ''
	for (var b = e; b < a; ++b) {
		var c = this.get(b)
		d += this.hexDigits.charAt(c >> 4) + this.hexDigits.charAt(c & 15)
		if ((b & 15) == 7) {
			d += ' '
		}
		d += (b & 15) == 15 ? '\n' : ' '
	}
	return d
}
Stream.prototype.parseStringISO = function (d, a) {
	var c = ''
	for (var b = d; b < a; ++b) {
		c += String.fromCharCode(this.get(b))
	}
	return c
}
Stream.prototype.parseStringUTF = function (f, a) {
	var d = '',
		e = 0
	for (var b = f; b < a; ) {
		var e = this.get(b++)
		if (e < 128) {
			d += String.fromCharCode(e)
		} else {
			if (e > 191 && e < 224) {
				d += String.fromCharCode(((e & 31) << 6) | (this.get(b++) & 63))
			} else {
				d += String.fromCharCode(((e & 15) << 12) | ((this.get(b++) & 63) << 6) | (this.get(b++) & 63))
			}
		}
	}
	return d
}
Stream.prototype.reTime = /^((?:1[89]|2\d)?\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([01]\d|2[0-3])(?:([0-5]\d)(?:([0-5]\d)(?:[.,](\d{1,3}))?)?)?(Z|[-+](?:[0]\d|1[0-2])([0-5]\d)?)?$/
Stream.prototype.parseTime = function (d, b) {
	var c = this.parseStringISO(d, b)
	var a = this.reTime.exec(c)
	if (!a) {
		return 'Unrecognized time: ' + c
	}
	c = a[1] + '-' + a[2] + '-' + a[3] + ' ' + a[4]
	if (a[5]) {
		c += ':' + a[5]
		if (a[6]) {
			c += ':' + a[6]
			if (a[7]) {
				c += '.' + a[7]
			}
		}
	}
	if (a[8]) {
		c += ' UTC'
		if (a[8] != 'Z') {
			c += a[8]
			if (a[9]) {
				c += ':' + a[9]
			}
		}
	}
	return c
}
Stream.prototype.parseInteger = function (d, a) {
	if (a - d > 4) {
		return undefined
	}
	var c = 0
	for (var b = d; b < a; ++b) {
		c = (c << 8) | this.get(b)
	}
	return c
}
Stream.prototype.parseOID = function (g, a) {
	var d,
		f = 0,
		e = 0
	for (var c = g; c < a; ++c) {
		var b = this.get(c)
		f = (f << 7) | (b & 127)
		e += 7
		if (!(b & 128)) {
			if (d == undefined) {
				d = parseInt(f / 40) + '.' + (f % 40)
			} else {
				d += '.' + (e >= 31 ? 'big' : f)
			}
			f = e = 0
		}
		d += String.fromCharCode()
	}
	return d
}
if (typeof pidCrypt != 'undefined') {
	pidCrypt.ASN1 = function (d, e, c, a, b) {
		this.stream = d
		this.header = e
		this.length = c
		this.tag = a
		this.sub = b
	}
	pidCrypt.ASN1.prototype.toHexTree = function () {
		var c = {}
		c.type = this.typeName()
		if (c.type != 'SEQUENCE') {
			c.value = this.stream.parseStringHex(this.posContent(), this.posEnd())
		}
		if (this.sub != null) {
			c.sub = []
			for (var b = 0, a = this.sub.length; b < a; ++b) {
				c.sub[b] = this.sub[b].toHexTree()
			}
		}
		return c
	}
	pidCrypt.ASN1.prototype.typeName = function () {
		if (this.tag == undefined) {
			return 'unknown'
		}
		var c = this.tag >> 6
		var a = (this.tag >> 5) & 1
		var b = this.tag & 31
		switch (c) {
			case 0:
				switch (b) {
					case 0:
						return 'EOC'
					case 1:
						return 'BOOLEAN'
					case 2:
						return 'INTEGER'
					case 3:
						return 'BIT_STRING'
					case 4:
						return 'OCTET_STRING'
					case 5:
						return 'NULL'
					case 6:
						return 'OBJECT_IDENTIFIER'
					case 7:
						return 'ObjectDescriptor'
					case 8:
						return 'EXTERNAL'
					case 9:
						return 'REAL'
					case 10:
						return 'ENUMERATED'
					case 11:
						return 'EMBEDDED_PDV'
					case 12:
						return 'UTF8String'
					case 16:
						return 'SEQUENCE'
					case 17:
						return 'SET'
					case 18:
						return 'NumericString'
					case 19:
						return 'PrintableString'
					case 20:
						return 'TeletexString'
					case 21:
						return 'VideotexString'
					case 22:
						return 'IA5String'
					case 23:
						return 'UTCTime'
					case 24:
						return 'GeneralizedTime'
					case 25:
						return 'GraphicString'
					case 26:
						return 'VisibleString'
					case 27:
						return 'GeneralString'
					case 28:
						return 'UniversalString'
					case 30:
						return 'BMPString'
					default:
						return 'Universal_' + b.toString(16)
				}
			case 1:
				return 'Application_' + b.toString(16)
			case 2:
				return '[' + b + ']'
			case 3:
				return 'Private_' + b.toString(16)
		}
	}
	pidCrypt.ASN1.prototype.content = function () {
		if (this.tag == undefined) {
			return null
		}
		var d = this.tag >> 6
		if (d != 0) {
			return null
		}
		var b = this.tag & 31
		var c = this.posContent()
		var a = Math.abs(this.length)
		switch (b) {
			case 1:
				return this.stream.get(c) == 0 ? 'false' : 'true'
			case 2:
				return this.stream.parseInteger(c, c + a)
			case 6:
				return this.stream.parseOID(c, c + a)
			case 12:
				return this.stream.parseStringUTF(c, c + a)
			case 18:
			case 19:
			case 20:
			case 21:
			case 22:
			case 26:
				return this.stream.parseStringISO(c, c + a)
			case 23:
			case 24:
				return this.stream.parseTime(c, c + a)
		}
		return null
	}
	pidCrypt.ASN1.prototype.toString = function () {
		return this.typeName() + '@' + this.stream.pos + '[header:' + this.header + ',length:' + this.length + ',sub:' + (this.sub == null ? 'null' : this.sub.length) + ']'
	}
	pidCrypt.ASN1.prototype.print = function (b) {
		if (b == undefined) {
			b = ''
		}
		document.writeln(b + this)
		if (this.sub != null) {
			b += '  '
			for (var c = 0, a = this.sub.length; c < a; ++c) {
				this.sub[c].print(b)
			}
		}
	}
	pidCrypt.ASN1.prototype.toPrettyString = function (b) {
		if (b == undefined) {
			b = ''
		}
		var d = b + this.typeName() + ' @' + this.stream.pos
		if (this.length >= 0) {
			d += '+'
		}
		d += this.length
		if (this.tag & 32) {
			d += ' (constructed)'
		} else {
			if ((this.tag == 3 || this.tag == 4) && this.sub != null) {
				d += ' (encapsulates)'
			}
		}
		d += '\n'
		if (this.sub != null) {
			b += '  '
			for (var c = 0, a = this.sub.length; c < a; ++c) {
				d += this.sub[c].toPrettyString(b)
			}
		}
		return d
	}
	pidCrypt.ASN1.prototype.toDOM = function () {
		var b = document.createElement('div')
		b.className = 'node'
		b.asn1 = this
		var g = document.createElement('div')
		g.className = 'head'
		var j = this.typeName()
		g.innerHTML = j
		b.appendChild(g)
		this.head = g
		var h = document.createElement('div')
		h.className = 'value'
		j = 'Offset: ' + this.stream.pos + '<br/>'
		j += 'Length: ' + this.header + '+'
		if (this.length >= 0) {
			j += this.length
		} else {
			j += -this.length + ' (undefined)'
		}
		if (this.tag & 32) {
			j += '<br/>(constructed)'
		} else {
			if ((this.tag == 3 || this.tag == 4) && this.sub != null) {
				j += '<br/>(encapsulates)'
			}
		}
		var e = this.content()
		if (e != null) {
			j += '<br/>Value:<br/><b>' + e + '</b>'
			if (typeof oids == 'object' && this.tag == 6) {
				var c = oids[e]
				if (c) {
					if (c.d) {
						j += '<br/>' + c.d
					}
					if (c.c) {
						j += '<br/>' + c.c
					}
					if (c.w) {
						j += '<br/>(warning!)'
					}
				}
			}
		}
		h.innerHTML = j
		b.appendChild(h)
		var a = document.createElement('div')
		a.className = 'sub'
		if (this.sub != null) {
			for (var d = 0, f = this.sub.length; d < f; ++d) {
				a.appendChild(this.sub[d].toDOM())
			}
		}
		b.appendChild(a)
		g.switchNode = b
		g.onclick = function () {
			var i = this.switchNode
			i.className = i.className == 'node collapsed' ? 'node' : 'node collapsed'
		}
		return b
	}
	pidCrypt.ASN1.prototype.posStart = function () {
		return this.stream.pos
	}
	pidCrypt.ASN1.prototype.posContent = function () {
		return this.stream.pos + this.header
	}
	pidCrypt.ASN1.prototype.posEnd = function () {
		return this.stream.pos + this.header + Math.abs(this.length)
	}
	pidCrypt.ASN1.prototype.toHexDOM_sub = function (d, c, e, f, a) {
		if (f >= a) {
			return
		}
		var b = document.createElement('span')
		b.className = c
		b.appendChild(document.createTextNode(e.hexDump(f, a)))
		d.appendChild(b)
	}
	pidCrypt.ASN1.prototype.toHexDOM = function () {
		var d = document.createElement('span')
		d.className = 'hex'
		this.head.hexNode = d
		this.head.onmouseover = function () {
			this.hexNode.className = 'hexCurrent'
		}
		this.head.onmouseout = function () {
			this.hexNode.className = 'hex'
		}
		this.toHexDOM_sub(d, 'tag', this.stream, this.posStart(), this.posStart() + 1)
		this.toHexDOM_sub(d, this.length >= 0 ? 'dlen' : 'ulen', this.stream, this.posStart() + 1, this.posContent())
		if (this.sub == null) {
			d.appendChild(document.createTextNode(this.stream.hexDump(this.posContent(), this.posEnd())))
		} else {
			if (this.sub.length > 0) {
				var e = this.sub[0]
				var c = this.sub[this.sub.length - 1]
				this.toHexDOM_sub(d, 'intro', this.stream, this.posContent(), e.posStart())
				for (var b = 0, a = this.sub.length; b < a; ++b) {
					d.appendChild(this.sub[b].toHexDOM())
				}
				this.toHexDOM_sub(d, 'outro', this.stream, c.posEnd(), this.posEnd())
			}
		}
		return d
	}
	pidCrypt.ASN1.decodeLength = function (d) {
		var b = d.get()
		var a = b & 127
		if (a == b) {
			return a
		}
		if (a > 3) {
			throw 'Length over 24 bits not supported at position ' + (d.pos - 1)
		}
		if (a == 0) {
			return -1
		}
		b = 0
		for (var c = 0; c < a; ++c) {
			b = (b << 8) | d.get()
		}
		return b
	}
	pidCrypt.ASN1.hasContent = function (b, a, g) {
		if (b & 32) {
			return true
		}
		if (b < 3 || b > 4) {
			return false
		}
		var f = new Stream(g)
		if (b == 3) {
			f.get()
		}
		var e = f.get()
		if ((e >> 6) & 1) {
			return false
		}
		try {
			var d = pidCrypt.ASN1.decodeLength(f)
			return f.pos - g.pos + d == a
		} catch (c) {
			return false
		}
	}
	pidCrypt.ASN1.decode = function (i) {
		if (!(i instanceof Stream)) {
			i = new Stream(i, 0)
		}
		var h = new Stream(i)
		var k = i.get()
		var f = pidCrypt.ASN1.decodeLength(i)
		var d = i.pos - h.pos
		var a = null
		if (pidCrypt.ASN1.hasContent(k, f, i)) {
			var b = i.pos
			if (k == 3) {
				i.get()
			}
			a = []
			if (f >= 0) {
				var c = b + f
				while (i.pos < c) {
					a[a.length] = pidCrypt.ASN1.decode(i)
				}
				if (i.pos != c) {
					throw 'Content size is not correct for container starting at offset ' + b
				}
			} else {
				try {
					for (;;) {
						var j = pidCrypt.ASN1.decode(i)
						if (j.tag == 0) {
							break
						}
						a[a.length] = j
					}
					f = b - i.pos
				} catch (g) {
					throw 'Exception while decoding undefined length content: ' + g
				}
			}
		} else {
			i.pos += f
		}
		return new pidCrypt.ASN1(h, d, f, k, a)
	}
	pidCrypt.ASN1.test = function () {
		var f = [
			{value: [39], expected: 39},
			{value: [129, 201], expected: 201},
			{value: [131, 254, 220, 186], expected: 16702650},
		]
		for (var c = 0, a = f.length; c < a; ++c) {
			var e = 0
			var d = new Stream(f[c].value, 0)
			var b = pidCrypt.ASN1.decodeLength(d)
			if (b != f[c].expected) {
				document.write('In test[' + c + '] expected ' + f[c].expected + ' got ' + b + '\n')
			}
		}
	}
}
/**
End asn1.js
Begin jsbn.js
**/
var dbits
var canary = 244837814094590
var j_lm = (canary & 16777215) == 15715070
function BigInteger(e, d, f) {
	if (e != null) {
		if ('number' == typeof e) {
			this.fromNumber(e, d, f)
		} else {
			if (d == null && 'string' != typeof e) {
				this.fromString(e, 256)
			} else {
				this.fromString(e, d)
			}
		}
	}
}
function nbi() {
	return new BigInteger(null)
}
function am1(f, a, b, e, h, g) {
	while (--g >= 0) {
		var d = a * this[f++] + b[e] + h
		h = Math.floor(d / 67108864)
		b[e++] = d & 67108863
	}
	return h
}
function am2(f, q, r, e, o, a) {
	var k = q & 32767,
		p = q >> 15
	while (--a >= 0) {
		var d = this[f] & 32767
		var g = this[f++] >> 15
		var b = p * d + g * k
		d = k * d + ((b & 32767) << 15) + r[e] + (o & 1073741823)
		o = (d >>> 30) + (b >>> 15) + p * g + (o >>> 30)
		r[e++] = d & 1073741823
	}
	return o
}
function am3(f, q, r, e, o, a) {
	var k = q & 16383,
		p = q >> 14
	while (--a >= 0) {
		var d = this[f] & 16383
		var g = this[f++] >> 14
		var b = p * d + g * k
		d = k * d + ((b & 16383) << 14) + r[e] + o
		o = (d >> 28) + (b >> 14) + p * g
		r[e++] = d & 268435455
	}
	return o
}
if (j_lm && typeof navigator !== 'undefined' && navigator.appName == 'Microsoft Internet Explorer') {
	BigInteger.prototype.am = am2
	dbits = 30
} else {
	if (j_lm && typeof navigator !== 'undefined' && navigator.appName != 'Netscape') {
		BigInteger.prototype.am = am1
		dbits = 26
	} else {
		BigInteger.prototype.am = am3
		dbits = 28
	}
}
BigInteger.prototype.DB = dbits
BigInteger.prototype.DM = (1 << dbits) - 1
BigInteger.prototype.DV = 1 << dbits
var BI_FP = 52
BigInteger.prototype.FV = Math.pow(2, BI_FP)
BigInteger.prototype.F1 = BI_FP - dbits
BigInteger.prototype.F2 = 2 * dbits - BI_FP
var BI_RM = '0123456789abcdefghijklmnopqrstuvwxyz'
var BI_RC = new Array()
var rr, vv
rr = '0'.charCodeAt(0)
for (vv = 0; vv <= 9; ++vv) {
	BI_RC[rr++] = vv
}
rr = 'a'.charCodeAt(0)
for (vv = 10; vv < 36; ++vv) {
	BI_RC[rr++] = vv
}
rr = 'A'.charCodeAt(0)
for (vv = 10; vv < 36; ++vv) {
	BI_RC[rr++] = vv
}
function int2char(a) {
	return BI_RM.charAt(a)
}
function intAt(b, a) {
	var d = BI_RC[b.charCodeAt(a)]
	return d == null ? -1 : d
}
function bnpCopyTo(b) {
	for (var a = this.t - 1; a >= 0; --a) {
		b[a] = this[a]
	}
	b.t = this.t
	b.s = this.s
}
function bnpFromInt(a) {
	this.t = 1
	this.s = a < 0 ? -1 : 0
	if (a > 0) {
		this[0] = a
	} else {
		if (a < -1) {
			this[0] = a + DV
		} else {
			this.t = 0
		}
	}
}
function nbv(a) {
	var b = nbi()
	b.fromInt(a)
	return b
}
function bnpFromString(h, c) {
	var e
	if (c == 16) {
		e = 4
	} else {
		if (c == 8) {
			e = 3
		} else {
			if (c == 256) {
				e = 8
			} else {
				if (c == 2) {
					e = 1
				} else {
					if (c == 32) {
						e = 5
					} else {
						if (c == 4) {
							e = 2
						} else {
							this.fromRadix(h, c)
							return
						}
					}
				}
			}
		}
	}
	this.t = 0
	this.s = 0
	var g = h.length,
		d = false,
		f = 0
	while (--g >= 0) {
		var a = e == 8 ? h[g] & 255 : intAt(h, g)
		if (a < 0) {
			if (h.charAt(g) == '-') {
				d = true
			}
			continue
		}
		d = false
		if (f == 0) {
			this[this.t++] = a
		} else {
			if (f + e > this.DB) {
				this[this.t - 1] |= (a & ((1 << (this.DB - f)) - 1)) << f
				this[this.t++] = a >> (this.DB - f)
			} else {
				this[this.t - 1] |= a << f
			}
		}
		f += e
		if (f >= this.DB) {
			f -= this.DB
		}
	}
	if (e == 8 && (h[0] & 128) != 0) {
		this.s = -1
		if (f > 0) {
			this[this.t - 1] |= ((1 << (this.DB - f)) - 1) << f
		}
	}
	this.clamp()
	if (d) {
		BigInteger.ZERO.subTo(this, this)
	}
}
function bnpClamp() {
	var a = this.s & this.DM
	while (this.t > 0 && this[this.t - 1] == a) {
		--this.t
	}
}
function bnToString(c) {
	if (this.s < 0) {
		return '-' + this.negate().toString(c)
	}
	var e
	if (c == 16) {
		e = 4
	} else {
		if (c == 8) {
			e = 3
		} else {
			if (c == 2) {
				e = 1
			} else {
				if (c == 32) {
					e = 5
				} else {
					if (c == 4) {
						e = 2
					} else {
						return this.toRadix(c)
					}
				}
			}
		}
	}
	var g = (1 << e) - 1,
		l,
		a = false,
		h = '',
		f = this.t
	var j = this.DB - ((f * this.DB) % e)
	if (f-- > 0) {
		if (j < this.DB && (l = this[f] >> j) > 0) {
			a = true
			h = int2char(l)
		}
		while (f >= 0) {
			if (j < e) {
				l = (this[f] & ((1 << j) - 1)) << (e - j)
				l |= this[--f] >> (j += this.DB - e)
			} else {
				l = (this[f] >> (j -= e)) & g
				if (j <= 0) {
					j += this.DB
					--f
				}
			}
			if (l > 0) {
				a = true
			}
			if (a) {
				h += int2char(l)
			}
		}
	}
	return a ? h : '0'
}
function bnNegate() {
	var a = nbi()
	BigInteger.ZERO.subTo(this, a)
	return a
}
function bnAbs() {
	return this.s < 0 ? this.negate() : this
}
function bnCompareTo(b) {
	var d = this.s - b.s
	if (d != 0) {
		return d
	}
	var c = this.t
	d = c - b.t
	if (d != 0) {
		return d
	}
	while (--c >= 0) {
		if ((d = this[c] - b[c]) != 0) {
			return d
		}
	}
	return 0
}
function nbits(a) {
	var c = 1,
		b
	if ((b = a >>> 16) != 0) {
		a = b
		c += 16
	}
	if ((b = a >> 8) != 0) {
		a = b
		c += 8
	}
	if ((b = a >> 4) != 0) {
		a = b
		c += 4
	}
	if ((b = a >> 2) != 0) {
		a = b
		c += 2
	}
	if ((b = a >> 1) != 0) {
		a = b
		c += 1
	}
	return c
}
function bnBitLength() {
	if (this.t <= 0) {
		return 0
	}
	return this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ (this.s & this.DM))
}
function bnpDLShiftTo(c, b) {
	var a
	for (a = this.t - 1; a >= 0; --a) {
		b[a + c] = this[a]
	}
	for (a = c - 1; a >= 0; --a) {
		b[a] = 0
	}
	b.t = this.t + c
	b.s = this.s
}
function bnpDRShiftTo(c, b) {
	for (var a = c; a < this.t; ++a) {
		b[a - c] = this[a]
	}
	b.t = Math.max(this.t - c, 0)
	b.s = this.s
}
function bnpLShiftTo(j, e) {
	var b = j % this.DB
	var a = this.DB - b
	var g = (1 << a) - 1
	var f = Math.floor(j / this.DB),
		h = (this.s << b) & this.DM,
		d
	for (d = this.t - 1; d >= 0; --d) {
		e[d + f + 1] = (this[d] >> a) | h
		h = (this[d] & g) << b
	}
	for (d = f - 1; d >= 0; --d) {
		e[d] = 0
	}
	e[f] = h
	e.t = this.t + f + 1
	e.s = this.s
	e.clamp()
}
function bnpRShiftTo(g, d) {
	d.s = this.s
	var e = Math.floor(g / this.DB)
	if (e >= this.t) {
		d.t = 0
		return
	}
	var b = g % this.DB
	var a = this.DB - b
	var f = (1 << b) - 1
	d[0] = this[e] >> b
	for (var c = e + 1; c < this.t; ++c) {
		d[c - e - 1] |= (this[c] & f) << a
		d[c - e] = this[c] >> b
	}
	if (b > 0) {
		d[this.t - e - 1] |= (this.s & f) << a
	}
	d.t = this.t - e
	d.clamp()
}
function bnpSubTo(d, f) {
	var e = 0,
		g = 0,
		b = Math.min(d.t, this.t)
	while (e < b) {
		g += this[e] - d[e]
		f[e++] = g & this.DM
		g >>= this.DB
	}
	if (d.t < this.t) {
		g -= d.s
		while (e < this.t) {
			g += this[e]
			f[e++] = g & this.DM
			g >>= this.DB
		}
		g += this.s
	} else {
		g += this.s
		while (e < d.t) {
			g -= d[e]
			f[e++] = g & this.DM
			g >>= this.DB
		}
		g -= d.s
	}
	f.s = g < 0 ? -1 : 0
	if (g < -1) {
		f[e++] = this.DV + g
	} else {
		if (g > 0) {
			f[e++] = g
		}
	}
	f.t = e
	f.clamp()
}
function bnpMultiplyTo(c, e) {
	var b = this.abs(),
		f = c.abs()
	var d = b.t
	e.t = d + f.t
	while (--d >= 0) {
		e[d] = 0
	}
	for (d = 0; d < f.t; ++d) {
		e[d + b.t] = b.am(0, f[d], e, d, 0, b.t)
	}
	e.s = 0
	e.clamp()
	if (this.s != c.s) {
		BigInteger.ZERO.subTo(e, e)
	}
}
function bnpSquareTo(d) {
	var a = this.abs()
	var b = (d.t = 2 * a.t)
	while (--b >= 0) {
		d[b] = 0
	}
	for (b = 0; b < a.t - 1; ++b) {
		var e = a.am(b, a[b], d, 2 * b, 0, 1)
		if ((d[b + a.t] += a.am(b + 1, 2 * a[b], d, 2 * b + 1, e, a.t - b - 1)) >= a.DV) {
			d[b + a.t] -= a.DV
			d[b + a.t + 1] = 1
		}
	}
	if (d.t > 0) {
		d[d.t - 1] += a.am(b, a[b], d, 2 * b, 0, 1)
	}
	d.s = 0
	d.clamp()
}
function bnpDivRemTo(n, h, g) {
	var w = n.abs()
	if (w.t <= 0) {
		return
	}
	var k = this.abs()
	if (k.t < w.t) {
		if (h != null) {
			h.fromInt(0)
		}
		if (g != null) {
			this.copyTo(g)
		}
		return
	}
	if (g == null) {
		g = nbi()
	}
	var d = nbi(),
		a = this.s,
		l = n.s
	var v = this.DB - nbits(w[w.t - 1])
	if (v > 0) {
		w.lShiftTo(v, d)
		k.lShiftTo(v, g)
	} else {
		w.copyTo(d)
		k.copyTo(g)
	}
	var p = d.t
	var b = d[p - 1]
	if (b == 0) {
		return
	}
	var o = b * (1 << this.F1) + (p > 1 ? d[p - 2] >> this.F2 : 0)
	var A = this.FV / o,
		z = (1 << this.F1) / o,
		x = 1 << this.F2
	var u = g.t,
		s = u - p,
		f = h == null ? nbi() : h
	d.dlShiftTo(s, f)
	if (g.compareTo(f) >= 0) {
		g[g.t++] = 1
		g.subTo(f, g)
	}
	BigInteger.ONE.dlShiftTo(p, f)
	f.subTo(d, d)
	while (d.t < p) {
		d[d.t++] = 0
	}
	while (--s >= 0) {
		var c = g[--u] == b ? this.DM : Math.floor(g[u] * A + (g[u - 1] + x) * z)
		if ((g[u] += d.am(0, c, g, s, 0, p)) < c) {
			d.dlShiftTo(s, f)
			g.subTo(f, g)
			while (g[u] < --c) {
				g.subTo(f, g)
			}
		}
	}
	if (h != null) {
		g.drShiftTo(p, h)
		if (a != l) {
			BigInteger.ZERO.subTo(h, h)
		}
	}
	g.t = p
	g.clamp()
	if (v > 0) {
		g.rShiftTo(v, g)
	}
	if (a < 0) {
		BigInteger.ZERO.subTo(g, g)
	}
}
function bnMod(b) {
	var c = nbi()
	this.abs().divRemTo(b, null, c)
	if (this.s < 0 && c.compareTo(BigInteger.ZERO) > 0) {
		b.subTo(c, c)
	}
	return c
}
function Classic(a) {
	this.m = a
}
function cConvert(a) {
	if (a.s < 0 || a.compareTo(this.m) >= 0) {
		return a.mod(this.m)
	} else {
		return a
	}
}
function cRevert(a) {
	return a
}
function cReduce(a) {
	a.divRemTo(this.m, null, a)
}
function cMulTo(a, c, b) {
	a.multiplyTo(c, b)
	this.reduce(b)
}
function cSqrTo(a, b) {
	a.squareTo(b)
	this.reduce(b)
}
Classic.prototype.convert = cConvert
Classic.prototype.revert = cRevert
Classic.prototype.reduce = cReduce
Classic.prototype.mulTo = cMulTo
Classic.prototype.sqrTo = cSqrTo
function bnpInvDigit() {
	if (this.t < 1) {
		return 0
	}
	var a = this[0]
	if ((a & 1) == 0) {
		return 0
	}
	var b = a & 3
	b = (b * (2 - (a & 15) * b)) & 15
	b = (b * (2 - (a & 255) * b)) & 255
	b = (b * (2 - (((a & 65535) * b) & 65535))) & 65535
	b = (b * (2 - ((a * b) % this.DV))) % this.DV
	return b > 0 ? this.DV - b : -b
}
function Montgomery(a) {
	this.m = a
	this.mp = a.invDigit()
	this.mpl = this.mp & 32767
	this.mph = this.mp >> 15
	this.um = (1 << (a.DB - 15)) - 1
	this.mt2 = 2 * a.t
}
function montConvert(a) {
	var b = nbi()
	a.abs().dlShiftTo(this.m.t, b)
	b.divRemTo(this.m, null, b)
	if (a.s < 0 && b.compareTo(BigInteger.ZERO) > 0) {
		this.m.subTo(b, b)
	}
	return b
}
function montRevert(a) {
	var b = nbi()
	a.copyTo(b)
	this.reduce(b)
	return b
}
function montReduce(a) {
	while (a.t <= this.mt2) {
		a[a.t++] = 0
	}
	for (var c = 0; c < this.m.t; ++c) {
		var b = a[c] & 32767
		var d = (b * this.mpl + (((b * this.mph + (a[c] >> 15) * this.mpl) & this.um) << 15)) & a.DM
		b = c + this.m.t
		a[b] += this.m.am(0, d, a, c, 0, this.m.t)
		while (a[b] >= a.DV) {
			a[b] -= a.DV
			a[++b]++
		}
	}
	a.clamp()
	a.drShiftTo(this.m.t, a)
	if (a.compareTo(this.m) >= 0) {
		a.subTo(this.m, a)
	}
}
function montSqrTo(a, b) {
	a.squareTo(b)
	this.reduce(b)
}
function montMulTo(a, c, b) {
	a.multiplyTo(c, b)
	this.reduce(b)
}
Montgomery.prototype.convert = montConvert
Montgomery.prototype.revert = montRevert
Montgomery.prototype.reduce = montReduce
Montgomery.prototype.mulTo = montMulTo
Montgomery.prototype.sqrTo = montSqrTo
function bnpIsEven() {
	return (this.t > 0 ? this[0] & 1 : this.s) == 0
}
function bnpExp(h, j) {
	if (h > 4294967295 || h < 1) {
		return BigInteger.ONE
	}
	var f = nbi(),
		a = nbi(),
		d = j.convert(this),
		c = nbits(h) - 1
	d.copyTo(f)
	while (--c >= 0) {
		j.sqrTo(f, a)
		if ((h & (1 << c)) > 0) {
			j.mulTo(a, d, f)
		} else {
			var b = f
			f = a
			a = b
		}
	}
	return j.revert(f)
}
function bnModPowInt(b, a) {
	var c
	if (b < 256 || a.isEven()) {
		c = new Classic(a)
	} else {
		c = new Montgomery(a)
	}
	return this.exp(b, c)
}
BigInteger.prototype.copyTo = bnpCopyTo
BigInteger.prototype.fromInt = bnpFromInt
BigInteger.prototype.fromString = bnpFromString
BigInteger.prototype.clamp = bnpClamp
BigInteger.prototype.dlShiftTo = bnpDLShiftTo
BigInteger.prototype.drShiftTo = bnpDRShiftTo
BigInteger.prototype.lShiftTo = bnpLShiftTo
BigInteger.prototype.rShiftTo = bnpRShiftTo
BigInteger.prototype.subTo = bnpSubTo
BigInteger.prototype.multiplyTo = bnpMultiplyTo
BigInteger.prototype.squareTo = bnpSquareTo
BigInteger.prototype.divRemTo = bnpDivRemTo
BigInteger.prototype.invDigit = bnpInvDigit
BigInteger.prototype.isEven = bnpIsEven
BigInteger.prototype.exp = bnpExp
BigInteger.prototype.toString = bnToString
BigInteger.prototype.negate = bnNegate
BigInteger.prototype.abs = bnAbs
BigInteger.prototype.compareTo = bnCompareTo
BigInteger.prototype.bitLength = bnBitLength
BigInteger.prototype.mod = bnMod
BigInteger.prototype.modPowInt = bnModPowInt
BigInteger.ZERO = nbv(0)
BigInteger.ONE = nbv(1)
function bnClone() {
	var a = nbi()
	this.copyTo(a)
	return a
}
function bnIntValue() {
	if (this.s < 0) {
		if (this.t == 1) {
			return this[0] - this.DV
		} else {
			if (this.t == 0) {
				return -1
			}
		}
	} else {
		if (this.t == 1) {
			return this[0]
		} else {
			if (this.t == 0) {
				return 0
			}
		}
	}
	return ((this[1] & ((1 << (32 - this.DB)) - 1)) << this.DB) | this[0]
}
function bnByteValue() {
	return this.t == 0 ? this.s : (this[0] << 24) >> 24
}
function bnShortValue() {
	return this.t == 0 ? this.s : (this[0] << 16) >> 16
}
function bnpChunkSize(a) {
	return Math.floor((Math.LN2 * this.DB) / Math.log(a))
}
function bnSigNum() {
	if (this.s < 0) {
		return -1
	} else {
		if (this.t <= 0 || (this.t == 1 && this[0] <= 0)) {
			return 0
		} else {
			return 1
		}
	}
}
function bnpToRadix(c) {
	if (c == null) {
		c = 10
	}
	if (this.signum() == 0 || c < 2 || c > 36) {
		return '0'
	}
	var f = this.chunkSize(c)
	var e = Math.pow(c, f)
	var i = nbv(e),
		j = nbi(),
		h = nbi(),
		g = ''
	this.divRemTo(i, j, h)
	while (j.signum() > 0) {
		g = (e + h.intValue()).toString(c).substr(1) + g
		j.divRemTo(i, j, h)
	}
	return h.intValue().toString(c) + g
}
function bnpFromRadix(m, h) {
	this.fromInt(0)
	if (h == null) {
		h = 10
	}
	var f = this.chunkSize(h)
	var g = Math.pow(h, f),
		e = false,
		a = 0,
		l = 0
	for (var c = 0; c < m.length; ++c) {
		var k = intAt(m, c)
		if (k < 0) {
			if (m.charAt(c) == '-' && this.signum() == 0) {
				e = true
			}
			continue
		}
		l = h * l + k
		if (++a >= f) {
			this.dMultiply(g)
			this.dAddOffset(l, 0)
			a = 0
			l = 0
		}
	}
	if (a > 0) {
		this.dMultiply(Math.pow(h, a))
		this.dAddOffset(l, 0)
	}
	if (e) {
		BigInteger.ZERO.subTo(this, this)
	}
}
function bnpFromNumber(f, e, h) {
	if ('number' == typeof e) {
		if (f < 2) {
			this.fromInt(1)
		} else {
			this.fromNumber(f, h)
			if (!this.testBit(f - 1)) {
				this.bitwiseTo(BigInteger.ONE.shiftLeft(f - 1), op_or, this)
			}
			if (this.isEven()) {
				this.dAddOffset(1, 0)
			}
			while (!this.isProbablePrime(e)) {
				this.dAddOffset(2, 0)
				if (this.bitLength() > f) {
					this.subTo(BigInteger.ONE.shiftLeft(f - 1), this)
				}
			}
		}
	} else {
		var d = new Array(),
			g = f & 7
		d.length = (f >> 3) + 1
		e.nextBytes(d)
		if (g > 0) {
			d[0] &= (1 << g) - 1
		} else {
			d[0] = 0
		}
		this.fromString(d, 256)
	}
}
function bnToByteArray() {
	var b = this.t,
		c = new Array()
	c[0] = this.s
	var e = this.DB - ((b * this.DB) % 8),
		f,
		a = 0
	if (b-- > 0) {
		if (e < this.DB && (f = this[b] >> e) != (this.s & this.DM) >> e) {
			c[a++] = f | (this.s << (this.DB - e))
		}
		while (b >= 0) {
			if (e < 8) {
				f = (this[b] & ((1 << e) - 1)) << (8 - e)
				f |= this[--b] >> (e += this.DB - 8)
			} else {
				f = (this[b] >> (e -= 8)) & 255
				if (e <= 0) {
					e += this.DB
					--b
				}
			}
			if ((f & 128) != 0) {
				f |= -256
			}
			if (a == 0 && (this.s & 128) != (f & 128)) {
				++a
			}
			if (a > 0 || f != this.s) {
				c[a++] = f
			}
		}
	}
	return c
}
function bnEquals(b) {
	return this.compareTo(b) == 0
}
function bnMin(b) {
	return this.compareTo(b) < 0 ? this : b
}
function bnMax(b) {
	return this.compareTo(b) > 0 ? this : b
}
function bnpBitwiseTo(c, h, e) {
	var d,
		g,
		b = Math.min(c.t, this.t)
	for (d = 0; d < b; ++d) {
		e[d] = h(this[d], c[d])
	}
	if (c.t < this.t) {
		g = c.s & this.DM
		for (d = b; d < this.t; ++d) {
			e[d] = h(this[d], g)
		}
		e.t = this.t
	} else {
		g = this.s & this.DM
		for (d = b; d < c.t; ++d) {
			e[d] = h(g, c[d])
		}
		e.t = c.t
	}
	e.s = h(this.s, c.s)
	e.clamp()
}
function op_and(a, b) {
	return a & b
}
function bnAnd(b) {
	var c = nbi()
	this.bitwiseTo(b, op_and, c)
	return c
}
function op_or(a, b) {
	return a | b
}
function bnOr(b) {
	var c = nbi()
	this.bitwiseTo(b, op_or, c)
	return c
}
function op_xor(a, b) {
	return a ^ b
}
function bnXor(b) {
	var c = nbi()
	this.bitwiseTo(b, op_xor, c)
	return c
}
function op_andnot(a, b) {
	return a & ~b
}
function bnAndNot(b) {
	var c = nbi()
	this.bitwiseTo(b, op_andnot, c)
	return c
}
function bnNot() {
	var b = nbi()
	for (var a = 0; a < this.t; ++a) {
		b[a] = this.DM & ~this[a]
	}
	b.t = this.t
	b.s = ~this.s
	return b
}
function bnShiftLeft(b) {
	var a = nbi()
	if (b < 0) {
		this.rShiftTo(-b, a)
	} else {
		this.lShiftTo(b, a)
	}
	return a
}
function bnShiftRight(b) {
	var a = nbi()
	if (b < 0) {
		this.lShiftTo(-b, a)
	} else {
		this.rShiftTo(b, a)
	}
	return a
}
function lbit(a) {
	if (a == 0) {
		return -1
	}
	var b = 0
	if ((a & 65535) == 0) {
		a >>= 16
		b += 16
	}
	if ((a & 255) == 0) {
		a >>= 8
		b += 8
	}
	if ((a & 15) == 0) {
		a >>= 4
		b += 4
	}
	if ((a & 3) == 0) {
		a >>= 2
		b += 2
	}
	if ((a & 1) == 0) {
		++b
	}
	return b
}
function bnGetLowestSetBit() {
	for (var a = 0; a < this.t; ++a) {
		if (this[a] != 0) {
			return a * this.DB + lbit(this[a])
		}
	}
	if (this.s < 0) {
		return this.t * this.DB
	}
	return -1
}
function cbit(a) {
	var b = 0
	while (a != 0) {
		a &= a - 1
		++b
	}
	return b
}
function bnBitCount() {
	var c = 0,
		a = this.s & this.DM
	for (var b = 0; b < this.t; ++b) {
		c += cbit(this[b] ^ a)
	}
	return c
}
function bnTestBit(b) {
	var a = Math.floor(b / this.DB)
	if (a >= this.t) {
		return this.s != 0
	}
	return (this[a] & (1 << b % this.DB)) != 0
}
function bnpChangeBit(c, b) {
	var a = BigInteger.ONE.shiftLeft(c)
	this.bitwiseTo(a, b, a)
	return a
}
function bnSetBit(a) {
	return this.changeBit(a, op_or)
}
function bnClearBit(a) {
	return this.changeBit(a, op_andnot)
}
function bnFlipBit(a) {
	return this.changeBit(a, op_xor)
}
function bnpAddTo(d, f) {
	var e = 0,
		g = 0,
		b = Math.min(d.t, this.t)
	while (e < b) {
		g += this[e] + d[e]
		f[e++] = g & this.DM
		g >>= this.DB
	}
	if (d.t < this.t) {
		g += d.s
		while (e < this.t) {
			g += this[e]
			f[e++] = g & this.DM
			g >>= this.DB
		}
		g += this.s
	} else {
		g += this.s
		while (e < d.t) {
			g += d[e]
			f[e++] = g & this.DM
			g >>= this.DB
		}
		g += d.s
	}
	f.s = g < 0 ? -1 : 0
	if (g > 0) {
		f[e++] = g
	} else {
		if (g < -1) {
			f[e++] = this.DV + g
		}
	}
	f.t = e
	f.clamp()
}
function bnAdd(b) {
	var c = nbi()
	this.addTo(b, c)
	return c
}
function bnSubtract(b) {
	var c = nbi()
	this.subTo(b, c)
	return c
}
function bnMultiply(b) {
	var c = nbi()
	this.multiplyTo(b, c)
	return c
}
function bnDivide(b) {
	var c = nbi()
	this.divRemTo(b, c, null)
	return c
}
function bnRemainder(b) {
	var c = nbi()
	this.divRemTo(b, null, c)
	return c
}
function bnDivideAndRemainder(b) {
	var d = nbi(),
		c = nbi()
	this.divRemTo(b, d, c)
	return new Array(d, c)
}
function bnpDMultiply(a) {
	this[this.t] = this.am(0, a - 1, this, 0, 0, this.t)
	++this.t
	this.clamp()
}
function bnpDAddOffset(b, a) {
	while (this.t <= a) {
		this[this.t++] = 0
	}
	this[a] += b
	while (this[a] >= this.DV) {
		this[a] -= this.DV
		if (++a >= this.t) {
			this[this.t++] = 0
		}
		++this[a]
	}
}
function NullExp() {}
function nNop(a) {
	return a
}
function nMulTo(a, c, b) {
	a.multiplyTo(c, b)
}
function nSqrTo(a, b) {
	a.squareTo(b)
}
NullExp.prototype.convert = nNop
NullExp.prototype.revert = nNop
NullExp.prototype.mulTo = nMulTo
NullExp.prototype.sqrTo = nSqrTo
function bnPow(a) {
	return this.exp(a, new NullExp())
}
function bnpMultiplyLowerTo(b, f, e) {
	var d = Math.min(this.t + b.t, f)
	e.s = 0
	e.t = d
	while (d > 0) {
		e[--d] = 0
	}
	var c
	for (c = e.t - this.t; d < c; ++d) {
		e[d + this.t] = this.am(0, b[d], e, d, 0, this.t)
	}
	for (c = Math.min(b.t, f); d < c; ++d) {
		this.am(0, b[d], e, d, 0, f - d)
	}
	e.clamp()
}
function bnpMultiplyUpperTo(b, e, d) {
	--e
	var c = (d.t = this.t + b.t - e)
	d.s = 0
	while (--c >= 0) {
		d[c] = 0
	}
	for (c = Math.max(e - this.t, 0); c < b.t; ++c) {
		d[this.t + c - e] = this.am(e - c, b[c], d, 0, 0, this.t + c - e)
	}
	d.clamp()
	d.drShiftTo(1, d)
}
function Barrett(a) {
	this.r2 = nbi()
	this.q3 = nbi()
	BigInteger.ONE.dlShiftTo(2 * a.t, this.r2)
	this.mu = this.r2.divide(a)
	this.m = a
}
function barrettConvert(a) {
	if (a.s < 0 || a.t > 2 * this.m.t) {
		return a.mod(this.m)
	} else {
		if (a.compareTo(this.m) < 0) {
			return a
		} else {
			var b = nbi()
			a.copyTo(b)
			this.reduce(b)
			return b
		}
	}
}
function barrettRevert(a) {
	return a
}
function barrettReduce(a) {
	a.drShiftTo(this.m.t - 1, this.r2)
	if (a.t > this.m.t + 1) {
		a.t = this.m.t + 1
		a.clamp()
	}
	this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3)
	this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2)
	while (a.compareTo(this.r2) < 0) {
		a.dAddOffset(1, this.m.t + 1)
	}
	a.subTo(this.r2, a)
	while (a.compareTo(this.m) >= 0) {
		a.subTo(this.m, a)
	}
}
function barrettSqrTo(a, b) {
	a.squareTo(b)
	this.reduce(b)
}
function barrettMulTo(a, c, b) {
	a.multiplyTo(c, b)
	this.reduce(b)
}
Barrett.prototype.convert = barrettConvert
Barrett.prototype.revert = barrettRevert
Barrett.prototype.reduce = barrettReduce
Barrett.prototype.mulTo = barrettMulTo
Barrett.prototype.sqrTo = barrettSqrTo
function bnModPow(q, f) {
	var o = q.bitLength(),
		h,
		b = nbv(1),
		v
	if (o <= 0) {
		return b
	} else {
		if (o < 18) {
			h = 1
		} else {
			if (o < 48) {
				h = 3
			} else {
				if (o < 144) {
					h = 4
				} else {
					if (o < 768) {
						h = 5
					} else {
						h = 6
					}
				}
			}
		}
	}
	if (o < 8) {
		v = new Classic(f)
	} else {
		if (f.isEven()) {
			v = new Barrett(f)
		} else {
			v = new Montgomery(f)
		}
	}
	var p = new Array(),
		d = 3,
		s = h - 1,
		a = (1 << h) - 1
	p[1] = v.convert(this)
	if (h > 1) {
		var A = nbi()
		v.sqrTo(p[1], A)
		while (d <= a) {
			p[d] = nbi()
			v.mulTo(A, p[d - 2], p[d])
			d += 2
		}
	}
	var l = q.t - 1,
		x,
		u = true,
		c = nbi(),
		y
	o = nbits(q[l]) - 1
	while (l >= 0) {
		if (o >= s) {
			x = (q[l] >> (o - s)) & a
		} else {
			x = (q[l] & ((1 << (o + 1)) - 1)) << (s - o)
			if (l > 0) {
				x |= q[l - 1] >> (this.DB + o - s)
			}
		}
		d = h
		while ((x & 1) == 0) {
			x >>= 1
			--d
		}
		if ((o -= d) < 0) {
			o += this.DB
			--l
		}
		if (u) {
			p[x].copyTo(b)
			u = false
		} else {
			while (d > 1) {
				v.sqrTo(b, c)
				v.sqrTo(c, b)
				d -= 2
			}
			if (d > 0) {
				v.sqrTo(b, c)
			} else {
				y = b
				b = c
				c = y
			}
			v.mulTo(c, p[x], b)
		}
		while (l >= 0 && (q[l] & (1 << o)) == 0) {
			v.sqrTo(b, c)
			y = b
			b = c
			c = y
			if (--o < 0) {
				o = this.DB - 1
				--l
			}
		}
	}
	return v.revert(b)
}
function bnGCD(c) {
	var b = this.s < 0 ? this.negate() : this.clone()
	var h = c.s < 0 ? c.negate() : c.clone()
	if (b.compareTo(h) < 0) {
		var e = b
		b = h
		h = e
	}
	var d = b.getLowestSetBit(),
		f = h.getLowestSetBit()
	if (f < 0) {
		return b
	}
	if (d < f) {
		f = d
	}
	if (f > 0) {
		b.rShiftTo(f, b)
		h.rShiftTo(f, h)
	}
	while (b.signum() > 0) {
		if ((d = b.getLowestSetBit()) > 0) {
			b.rShiftTo(d, b)
		}
		if ((d = h.getLowestSetBit()) > 0) {
			h.rShiftTo(d, h)
		}
		if (b.compareTo(h) >= 0) {
			b.subTo(h, b)
			b.rShiftTo(1, b)
		} else {
			h.subTo(b, h)
			h.rShiftTo(1, h)
		}
	}
	if (f > 0) {
		h.lShiftTo(f, h)
	}
	return h
}
function bnpModInt(e) {
	if (e <= 0) {
		return 0
	}
	var c = this.DV % e,
		b = this.s < 0 ? e - 1 : 0
	if (this.t > 0) {
		if (c == 0) {
			b = this[0] % e
		} else {
			for (var a = this.t - 1; a >= 0; --a) {
				b = (c * b + this[a]) % e
			}
		}
	}
	return b
}
function bnModInverse(f) {
	var j = f.isEven()
	if ((this.isEven() && j) || f.signum() == 0) {
		return BigInteger.ZERO
	}
	var i = f.clone(),
		h = this.clone()
	var g = nbv(1),
		e = nbv(0),
		l = nbv(0),
		k = nbv(1)
	while (i.signum() != 0) {
		while (i.isEven()) {
			i.rShiftTo(1, i)
			if (j) {
				if (!g.isEven() || !e.isEven()) {
					g.addTo(this, g)
					e.subTo(f, e)
				}
				g.rShiftTo(1, g)
			} else {
				if (!e.isEven()) {
					e.subTo(f, e)
				}
			}
			e.rShiftTo(1, e)
		}
		while (h.isEven()) {
			h.rShiftTo(1, h)
			if (j) {
				if (!l.isEven() || !k.isEven()) {
					l.addTo(this, l)
					k.subTo(f, k)
				}
				l.rShiftTo(1, l)
			} else {
				if (!k.isEven()) {
					k.subTo(f, k)
				}
			}
			k.rShiftTo(1, k)
		}
		if (i.compareTo(h) >= 0) {
			i.subTo(h, i)
			if (j) {
				g.subTo(l, g)
			}
			e.subTo(k, e)
		} else {
			h.subTo(i, h)
			if (j) {
				l.subTo(g, l)
			}
			k.subTo(e, k)
		}
	}
	if (h.compareTo(BigInteger.ONE) != 0) {
		return BigInteger.ZERO
	}
	if (k.compareTo(f) >= 0) {
		return k.subtract(f)
	}
	if (k.signum() < 0) {
		k.addTo(f, k)
	} else {
		return k
	}
	if (k.signum() < 0) {
		return k.add(f)
	} else {
		return k
	}
}
var lowprimes = [
	2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439,
	443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509,
]
var lplim = (1 << 26) / lowprimes[lowprimes.length - 1]
function bnIsProbablePrime(e) {
	var d,
		b = this.abs()
	if (b.t == 1 && b[0] <= lowprimes[lowprimes.length - 1]) {
		for (d = 0; d < lowprimes.length; ++d) {
			if (b[0] == lowprimes[d]) {
				return true
			}
		}
		return false
	}
	if (b.isEven()) {
		return false
	}
	d = 1
	while (d < lowprimes.length) {
		var a = lowprimes[d],
			c = d + 1
		while (c < lowprimes.length && a < lplim) {
			a *= lowprimes[c++]
		}
		a = b.modInt(a)
		while (d < c) {
			if (a % lowprimes[d++] == 0) {
				return false
			}
		}
	}
	return b.millerRabin(e)
}
function bnpMillerRabin(f) {
	var g = this.subtract(BigInteger.ONE)
	var c = g.getLowestSetBit()
	if (c <= 0) {
		return false
	}
	var h = g.shiftRight(c)
	f = (f + 1) >> 1
	if (f > lowprimes.length) {
		f = lowprimes.length
	}
	var b = nbi()
	for (var e = 0; e < f; ++e) {
		b.fromInt(lowprimes[e])
		var l = b.modPow(h, this)
		if (l.compareTo(BigInteger.ONE) != 0 && l.compareTo(g) != 0) {
			var d = 1
			while (d++ < c && l.compareTo(g) != 0) {
				l = l.modPowInt(2, this)
				if (l.compareTo(BigInteger.ONE) == 0) {
					return false
				}
			}
			if (l.compareTo(g) != 0) {
				return false
			}
		}
	}
	return true
}
BigInteger.prototype.chunkSize = bnpChunkSize
BigInteger.prototype.toRadix = bnpToRadix
BigInteger.prototype.fromRadix = bnpFromRadix
BigInteger.prototype.fromNumber = bnpFromNumber
BigInteger.prototype.bitwiseTo = bnpBitwiseTo
BigInteger.prototype.changeBit = bnpChangeBit
BigInteger.prototype.addTo = bnpAddTo
BigInteger.prototype.dMultiply = bnpDMultiply
BigInteger.prototype.dAddOffset = bnpDAddOffset
BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo
BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo
BigInteger.prototype.modInt = bnpModInt
BigInteger.prototype.millerRabin = bnpMillerRabin
BigInteger.prototype.clone = bnClone
BigInteger.prototype.intValue = bnIntValue
BigInteger.prototype.byteValue = bnByteValue
BigInteger.prototype.shortValue = bnShortValue
BigInteger.prototype.signum = bnSigNum
BigInteger.prototype.toByteArray = bnToByteArray
BigInteger.prototype.equals = bnEquals
BigInteger.prototype.min = bnMin
BigInteger.prototype.max = bnMax
BigInteger.prototype.and = bnAnd
BigInteger.prototype.or = bnOr
BigInteger.prototype.xor = bnXor
BigInteger.prototype.andNot = bnAndNot
BigInteger.prototype.not = bnNot
BigInteger.prototype.shiftLeft = bnShiftLeft
BigInteger.prototype.shiftRight = bnShiftRight
BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit
BigInteger.prototype.bitCount = bnBitCount
BigInteger.prototype.testBit = bnTestBit
BigInteger.prototype.setBit = bnSetBit
BigInteger.prototype.clearBit = bnClearBit
BigInteger.prototype.flipBit = bnFlipBit
BigInteger.prototype.add = bnAdd
BigInteger.prototype.subtract = bnSubtract
BigInteger.prototype.multiply = bnMultiply
BigInteger.prototype.divide = bnDivide
BigInteger.prototype.remainder = bnRemainder
BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder
BigInteger.prototype.modPow = bnModPow
BigInteger.prototype.modInverse = bnModInverse
BigInteger.prototype.pow = bnPow
BigInteger.prototype.gcd = bnGCD
BigInteger.prototype.isProbablePrime = bnIsProbablePrime
/**
End jsbn.js
Begin prng4.js
**/
function Arcfour() {
	this.i = 0
	this.j = 0
	this.S = new Array()
}
function ARC4init(d) {
	var c, a, b
	for (c = 0; c < 256; ++c) {
		this.S[c] = c
	}
	a = 0
	for (c = 0; c < 256; ++c) {
		a = (a + this.S[c] + d[c % d.length]) & 255
		b = this.S[c]
		this.S[c] = this.S[a]
		this.S[a] = b
	}
	this.i = 0
	this.j = 0
}
function ARC4next() {
	var a
	this.i = (this.i + 1) & 255
	this.j = (this.j + this.S[this.i]) & 255
	a = this.S[this.i]
	this.S[this.i] = this.S[this.j]
	this.S[this.j] = a
	return this.S[(a + this.S[this.i]) & 255]
}
Arcfour.prototype.init = ARC4init
Arcfour.prototype.next = ARC4next
function prng_newstate() {
	return new Arcfour()
}
var rng_psize = 256
/**
End prng4.js
Begin rng.js
**/
function SecureRandom() {
	this.rng_state
	this.rng_pool
	this.rng_pptr
	this.rng_seed_int = function (c) {
		this.rng_pool[this.rng_pptr++] ^= c & 255
		this.rng_pool[this.rng_pptr++] ^= (c >> 8) & 255
		this.rng_pool[this.rng_pptr++] ^= (c >> 16) & 255
		this.rng_pool[this.rng_pptr++] ^= (c >> 24) & 255
		if (this.rng_pptr >= rng_psize) {
			this.rng_pptr -= rng_psize
		}
	}
	this.rng_seed_time = function () {
		this.rng_seed_int(new Date().getTime())
	}
	if (this.rng_pool == null) {
		this.rng_pool = new Array()
		this.rng_pptr = 0
		var a
		if (typeof navigator !== 'undefined' && navigator.appName == 'Netscape' && navigator.appVersion < '5' && window.crypto) {
			var b = window.crypto.random(32)
			for (a = 0; a < b.length; ++a) {
				this.rng_pool[this.rng_pptr++] = b.charCodeAt(a) & 255
			}
		}
		while (this.rng_pptr < rng_psize) {
			a = Math.floor(65536 * Math.random())
			this.rng_pool[this.rng_pptr++] = a >>> 8
			this.rng_pool[this.rng_pptr++] = a & 255
		}
		this.rng_pptr = 0
		this.rng_seed_time()
	}
	this.rng_get_byte = function () {
		if (this.rng_state == null) {
			this.rng_seed_time()
			this.rng_state = prng_newstate()
			this.rng_state.init(this.rng_pool)
			for (this.rng_pptr = 0; this.rng_pptr < this.rng_pool.length; ++this.rng_pptr) {
				this.rng_pool[this.rng_pptr] = 0
			}
			this.rng_pptr = 0
		}
		return this.rng_state.next()
	}
	this.nextBytes = function (d) {
		var c
		for (c = 0; c < d.length; ++c) {
			d[c] = this.rng_get_byte()
		}
	}
}
/**
End rng.js
Begin rsa.js
**/
if (typeof pidCrypt != 'undefined' && typeof BigInteger != 'undefined' && typeof SecureRandom != 'undefined' && typeof Arcfour != 'undefined') {
	function parseBigInt(b, a) {
		return new BigInteger(b, a)
	}
	function linebrk(c, d) {
		var a = ''
		var b = 0
		while (b + d < c.length) {
			a += c.substring(b, b + d) + '\n'
			b += d
		}
		return a + c.substring(b, c.length)
	}
	function byte2Hex(a) {
		if (a < 16) {
			return '0' + a.toString(16)
		} else {
			return a.toString(16)
		}
	}
	function pkcs1unpad2(f, g) {
		var a = f.toByteArray()
		var e = 0
		while (e < a.length && a[e] == 0) {
			++e
		}
		if (a.length - e != g - 1 || a[e] != 2) {
			return null
		}
		++e
		while (a[e] != 0) {
			if (++e >= a.length) {
				return null
			}
		}
		var c = ''
		while (++e < a.length) {
			c += String.fromCharCode(a[e])
		}
		return c
	}
	function pkcs1pad2(d, f) {
		if (f < d.length + 11) {
			console.log('Message too long for RSA')
			return null
		}
		var e = new Array()
		var c = d.length - 1
		while (c >= 0 && f > 0) {
			e[--f] = d.charCodeAt(c--)
		}
		e[--f] = 0
		var b = new SecureRandom()
		var a = new Array()
		while (f > 2) {
			a[0] = 0
			while (a[0] == 0) {
				b.nextBytes(a)
			}
			e[--f] = a[0]
		}
		e[--f] = 2
		e[--f] = 0
		return new BigInteger(e)
	}
	pidCrypt.RSA = function () {
		this.n = null
		this.e = 0
		this.d = null
		this.p = null
		this.q = null
		this.dmp1 = null
		this.dmq1 = null
		this.coeff = null
	}
	pidCrypt.RSA.prototype.doPrivate = function (a) {
		if (this.p == null || this.q == null) {
			return a.modPow(this.d, this.n)
		}
		var c = a.mod(this.p).modPow(this.dmp1, this.p)
		var b = a.mod(this.q).modPow(this.dmq1, this.q)
		while (c.compareTo(b) < 0) {
			c = c.add(this.p)
		}
		return c.subtract(b).multiply(this.coeff).mod(this.p).multiply(this.q).add(b)
	}
	pidCrypt.RSA.prototype.setPublic = function (c, b, a) {
		if (typeof a == 'undefined') {
			a = 16
		}
		if (c != null && b != null && c.length > 0 && b.length > 0) {
			this.n = parseBigInt(c, a)
			this.e = parseInt(b, a)
		} else {
			console.log('Invalid RSA public key')
		}
	}
	pidCrypt.RSA.prototype.doPublic = function (a) {
		return a.modPowInt(this.e, this.n)
	}
	pidCrypt.RSA.prototype.encryptRaw = function (d) {
		var a = pkcs1pad2(d, (this.n.bitLength() + 7) >> 3)
		if (a == null) {
			return null
		}
		var e = this.doPublic(a)
		if (e == null) {
			return null
		}
		var b = e.toString(16)
		if ((b.length & 1) == 0) {
			return b
		} else {
			return '0' + b
		}
	}
	pidCrypt.RSA.prototype.encrypt = function (a) {
		a = pidCryptUtil.encodeBase64(a)
		return this.encryptRaw(a)
	}
	pidCrypt.RSA.prototype.decryptRaw = function (b) {
		var d = parseBigInt(b, 16)
		var a = this.doPrivate(d)
		if (a == null) {
			return null
		}
		return pkcs1unpad2(a, (this.n.bitLength() + 7) >> 3)
	}
	pidCrypt.RSA.prototype.decrypt = function (b) {
		var a = this.decryptRaw(b)
		a = a ? pidCryptUtil.decodeBase64(a) : ''
		return a
	}
	pidCrypt.RSA.prototype.setPrivate = function (d, b, c, a) {
		if (typeof a == 'undefined') {
			a = 16
		}
		if (d != null && b != null && d.length > 0 && b.length > 0) {
			this.n = parseBigInt(d, a)
			this.e = parseInt(b, a)
			this.d = parseBigInt(c, a)
		} else {
			console.log('Invalid RSA private key')
		}
	}
	pidCrypt.RSA.prototype.setPrivateEx = function (e, i, a, d, c, h, g, b, f) {
		if (typeof f == 'undefined') {
			f = 16
		}
		if (e != null && i != null && e.length > 0 && i.length > 0) {
			this.n = parseBigInt(e, f)
			this.e = parseInt(i, f)
			this.d = parseBigInt(a, f)
			this.p = parseBigInt(d, f)
			this.q = parseBigInt(c, f)
			this.dmp1 = parseBigInt(h, f)
			this.dmq1 = parseBigInt(g, f)
			this.coeff = parseBigInt(b, f)
		} else {
			console.log('Invalid RSA private key')
		}
	}
	pidCrypt.RSA.prototype.generate = function (b, i) {
		var a = new SecureRandom()
		var f = b >> 1
		this.e = parseInt(i, 16)
		var c = new BigInteger(i, 16)
		for (;;) {
			for (;;) {
				this.p = new BigInteger(b - f, 1, a)
				if (this.p.subtract(BigInteger.ONE).gcd(c).compareTo(BigInteger.ONE) == 0 && this.p.isProbablePrime(10)) {
					break
				}
			}
			for (;;) {
				this.q = new BigInteger(f, 1, a)
				if (this.q.subtract(BigInteger.ONE).gcd(c).compareTo(BigInteger.ONE) == 0 && this.q.isProbablePrime(10)) {
					break
				}
			}
			if (this.p.compareTo(this.q) <= 0) {
				var h = this.p
				this.p = this.q
				this.q = h
			}
			var g = this.p.subtract(BigInteger.ONE)
			var d = this.q.subtract(BigInteger.ONE)
			var e = g.multiply(d)
			if (e.gcd(c).compareTo(BigInteger.ONE) == 0) {
				this.n = this.p.multiply(this.q)
				this.d = c.modInverse(e)
				this.dmp1 = this.d.mod(g)
				this.dmq1 = this.d.mod(d)
				this.coeff = this.q.modInverse(this.p)
				break
			}
		}
	}
	pidCrypt.RSA.prototype.getASNData = function (a) {
		var e = {}
		var c = []
		var d = 0
		if (a.value && a.type == 'INTEGER') {
			c[d++] = a.value
		}
		if (a.sub) {
			for (var b = 0; b < a.sub.length; b++) {
				c = c.concat(this.getASNData(a.sub[b]))
			}
		}
		return c
	}
	pidCrypt.RSA.prototype.setKeyFromASN = function (c, e) {
		var d = ['N', 'E', 'D', 'P', 'Q', 'DP', 'DQ', 'C']
		var f = {}
		var a = this.getASNData(e)
		switch (c) {
			case 'Public':
			case 'public':
				for (var b = 0; b < a.length; b++) {
					f[d[b]] = a[b].toLowerCase()
				}
				this.setPublic(f.N, f.E, 16)
				break
			case 'Private':
			case 'private':
				for (var b = 1; b < a.length; b++) {
					f[d[b - 1]] = a[b].toLowerCase()
				}
				this.setPrivateEx(f.N, f.E, f.D, f.P, f.Q, f.DP, f.DQ, f.C, 16)
				break
		}
	}
	pidCrypt.RSA.prototype.setPublicKeyFromASN = function (a) {
		this.setKeyFromASN('public', a)
	}
	pidCrypt.RSA.prototype.setPrivateKeyFromASN = function (a) {
		this.setKeyFromASN('private', a)
	}
	pidCrypt.RSA.prototype.getParameters = function () {
		var a = {}
		if (this.n != null) {
			a.n = this.n
		}
		a.e = this.e
		if (this.d != null) {
			a.d = this.d
		}
		if (this.p != null) {
			a.p = this.p
		}
		if (this.q != null) {
			a.q = this.q
		}
		if (this.dmp1 != null) {
			a.dmp1 = this.dmp1
		}
		if (this.dmq1 != null) {
			a.dmq1 = this.dmq1
		}
		if (this.coeff != null) {
			a.c = this.coeff
		}
		return a
	}
}
/**
End rsa.js

End pidCrypt Library.
**/
