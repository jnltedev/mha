export function decodeMimeWords(input) {
  if (!input) return input;
  const collapsed = input.replace(/(\?=)(\s+)(=\?)/g, '$1$3');
  return collapsed.replace(/=\?([^?\s]+)\?([QqBb])\?([^?]*)\?=/g, (match, charset, enc, text) => {
    try {
      let bytes;
      if (enc.toLowerCase() === 'b') {
        const bin = atob(text.replace(/\s+/g, ''));
        bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
      } else {
        const arr = [];
        for (let i = 0; i < text.length; i++) {
          const c = text[i];
          if (c === '_') {
            arr.push(0x20);
          } else if (c === '=' && i + 2 < text.length) {
            arr.push(parseInt(text.substr(i + 1, 2), 16));
            i += 2;
          } else {
            arr.push(c.charCodeAt(0));
          }
        }
        bytes = Uint8Array.from(arr);
      }
      return new TextDecoder(charset.toLowerCase()).decode(bytes);
    } catch {
      return match;
    }
  });
}
