---
layout: post
title: JavaScript problem? - picoCTF 2019 Java Script Kiddle
tags: [CTF, web]
---
> The image link appears broken... https://jupiter.challenges.picoctf.org/problem/58112 or http://jupiter.challenges.picoctf.org:58112
>
> Hint: This is only a JavaScript problem.

The webpage shows a text input box with a submit button. Let's take a look at the source code.
```html
<html>
	<head>    
		<script src="jquery-3.3.1.min.js"></script>
		<script>
			var bytes = [];
			$.get("bytes", function(resp) {
				bytes = Array.from(resp.split(" "), x => Number(x));
			});

			function assemble_png(u_in){
				var LEN = 16;
				var key = "0000000000000000";
				var shifter;
				if(u_in.length == LEN){
					key = u_in;
				}
				var result = [];
				for(var i = 0; i < LEN; i++){
					shifter = key.charCodeAt(i) - 48;
					for(var j = 0; j < (bytes.length / LEN); j ++){
						result[(j * LEN) + i] = bytes[(((j + shifter) * LEN) % bytes.length) + i]
					}
				}
				while(result[result.length-1] == 0){
					result = result.slice(0,result.length-1);
				}
				document.getElementById("Area").src = "data:image/png;base64," + btoa(String.fromCharCode.apply(null, new Uint8Array(result)));
				return false;
			}
		</script>
	</head>
	<body>

		<center>
			<form action="#" onsubmit="assemble_png(document.getElementById('user_in').value)">
				<input type="text" id="user_in">
				<input type="submit" value="Submit">
			</form>
			<img id="Area" src=""/>
		</center>

	</body>
</html>
```
The webpage
1. Gets some bytes from `/bytes`
2. Uses the user input to swap columns of the bytes (if cosidered as 2D array)
3. Render the picture

So the result of swapping should be valid PNG file, as mentioned here
```js
document.getElementById("Area").src = "data:image/png;base64," + btoa(String.fromCharCode.apply(null, new Uint8Array(result)));
```
A valid PNG file should starts with the magic header (in HEX)
```
89 50 4E 47 0D 0A 1A 0A
```
Also the following 8 bytes would be first chunk, which is the **IHDR** chunk, with length `0x0d`. So the first 16 bytes would be
```
| 89 50 4E 47 0D 0A 1A 0A | 00 00 00 0d | 49 48 44 52 |
|          magic          |    length   |     type    |
```
Just test each byte to get the possible value each key value
```
❯ node chall.js
Length = 672
Possible key[0] = 4
Possible key[1] = 8
Possible key[2] = 9
Possible key[3] = 4
Possible key[4] = 7
Possible key[5] = 4
Possible key[6] = 8
Possible key[7] = 4
Possible key[8] = 8
Possible key[9] = 5,6
Possible key[10] = 1,2
Possible key[11] = 6
Possible key[12] = 7
Possible key[13] = 1
Possible key[14] = 0
Possible key[15] = 4
```
Four possible key: `4894748485167104`, `4894748485267104`, `4894748486167104`, `4894748486267104`. Eventually the first one works, which will render a QRCode. Decode it and get the flag.

The solution script is the following
```js
var bytes_raw = '128 252 182 115 177 211 142 252 189 248 130 93 154 0 68 90 131 255 204 170 239 167 18 51 233 43 0 26 210 72 95 120 227 7 195 126 207 254 115 53 141 217 0 11 118 192 110 0 0 170 248 73 103 78 10 174 208 233 156 187 185 65 228 0 137 128 228 71 159 10 111 10 29 96 71 238 141 86 91 82 0 214 37 114 7 0 238 114 133 0 140 0 38 36 144 108 164 141 63 2 69 73 15 65 68 0 249 13 0 64 111 220 48 0 55 255 13 12 68 41 66 120 188 0 73 27 173 72 189 80 0 148 0 64 26 123 0 32 44 237 0 252 36 19 52 0 78 227 98 88 1 185 1 128 182 177 155 44 132 162 68 0 1 239 175 248 68 91 84 18 223 223 111 83 26 188 241 12 0 197 57 89 116 96 223 96 161 45 133 127 125 63 80 129 69 59 241 157 0 105 57 23 30 241 62 229 128 91 39 152 125 146 216 91 5 217 16 48 159 4 198 23 108 178 199 14 6 175 51 154 227 45 56 140 221 0 230 228 99 239 132 198 133 72 243 93 3 86 94 246 156 153 123 1 204 200 233 143 127 64 164 203 36 24 2 169 121 122 159 40 4 25 64 0 241 9 94 220 254 221 122 8 22 227 140 221 248 250 141 66 78 126 190 73 248 105 5 14 26 19 119 223 103 165 69 177 68 61 195 239 115 199 126 61 41 242 175 85 211 11 5 250 93 79 194 78 245 223 255 189 0 128 9 150 178 0 112 247 210 21 36 0 2 252 144 59 101 164 185 94 232 59 150 255 187 1 198 171 182 228 147 73 149 47 92 133 147 254 173 242 39 254 223 214 196 135 248 34 146 206 63 127 127 22 191 92 88 69 23 142 167 237 248 23 215 148 166 59 243 248 173 210 169 254 209 157 174 192 32 228 41 192 245 47 207 120 139 28 224 249 29 55 221 109 226 21 129 75 41 113 192 147 45 144 55 228 126 250 127 197 184 155 251 19 220 11 241 171 229 213 79 135 93 49 94 144 38 250 121 113 58 114 77 111 157 146 242 175 236 185 60 67 173 103 233 234 60 248 27 242 115 223 207 218 203 115 47 252 241 152 24 165 115 126 48 76 104 126 42 225 226 211 57 252 239 21 195 205 107 255 219 132 148 81 171 53 79 91 27 174 235 124 213 71 221 243 212 38 224 124 54 77 248 252 88 163 44 191 109 63 189 231 251 189 242 141 246 249 15 0 2 230 7 244 161 31 42 182 219 15 221 164 252 207 53 95 99 60 190 232 78 255 197 16 169 252 100 164 19 158 32 189 126 140 145 158 116 245 68 94 149 111 252 74 135 189 83 74 71 218 99 220 208 87 24 228 11 111 245 1 0 98 131 46 22 94 71 244 22 147 21 83 155 252 243 90 24 59 73 247 223 127 242 183 251 124 28 245 222 199 248 122 204 230 79 219 147 11 225 202 239 24 132 55 89 221 143 151 137 63 150 79 211 8 16 4 60 63 99 65 0 2'
var bytes = Array.from(bytes_raw.split(' '), x => Number(x))
console.log(`Length = ${bytes.length}`)

function assemble_png(u_in){
  var LEN = 16;
  var key = "0000000000000000";
  var shifter;
  if(u_in.length == LEN){
    key = u_in;
  }
  var result = [];
  for(var i = 0; i < LEN; i++){
    shifter = key.charCodeAt(i) - 48;
    for(var j = 0; j < (bytes.length / LEN); j ++){
      result[(j * LEN) + i] = bytes[(((j + shifter) * LEN) % bytes.length) + i]
    }
  }
  while(result[result.length-1] == 0){
    result = result.slice(0,result.length-1);
  }
  // document.getElementById("Area").src = "data:image/png;base64," + btoa(String.fromCharCode.apply(null, new Uint8Array(result)));
  return result
}

const magic = [137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 0x0d, 0x49, 0x48, 0x44, 0x52]
var testkey = "0000000000000000"

for (var idx = 0; idx < 16; idx++) {
  var res = []
  for (var i = 48; i < 58; i++) {
    testkey = testkey.substring(0, idx) + String.fromCharCode(i) + testkey.substring(idx + 1);
    if (assemble_png(testkey)[idx] === magic[idx]) res.push(i - 48);
  }
  console.log(`Possible key[${idx}] = ${res}`);
}
```
`picoCTF{7b15cfb95f05286e37a22dda25935e1e}`