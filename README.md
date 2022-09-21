# KTA CC Encrypt

A tool to build encrypted XML for Credit Card payments.

## Install

`npm i --save kta-cc-encrypt`

## Usage

```
import buildXML from 'kta-cc-encrypt'

const {PAN, ExpDate, CVV} = {
	PAN: '1234567890123456',
	ExpDate: '05/23',
	CVV: '456',
}

const encryptedData = buildXML(PAN, ExpDate, CVV)
```
