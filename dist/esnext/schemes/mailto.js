import { pctEncChar, pctDecChars, unescapeComponent } from "../uri";
import punycode from "punycode";
import { merge, subexp, toUpperCase, toArray } from "../util";
const O = {};
const isIRI = true;
//RFC 3986
const UNRESERVED$$ = "[A-Za-z0-9\\-\\.\\_\\~" + (isIRI ? "\\xA0-\\u200D\\u2010-\\u2029\\u202F-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF" : "") + "]";
const HEXDIG$$ = "[0-9A-Fa-f]"; //case-insensitive
const PCT_ENCODED$ = subexp(subexp("%[EFef]" + HEXDIG$$ + "%" + HEXDIG$$ + HEXDIG$$ + "%" + HEXDIG$$ + HEXDIG$$) + "|" + subexp("%[89A-Fa-f]" + HEXDIG$$ + "%" + HEXDIG$$ + HEXDIG$$) + "|" + subexp("%" + HEXDIG$$ + HEXDIG$$)); //expanded
//RFC 5322, except these symbols as per RFC 6068: @ : / ? # [ ] & ; =
//const ATEXT$$ = "[A-Za-z0-9\\!\\#\\$\\%\\&\\'\\*\\+\\-\\/\\=\\?\\^\\_\\`\\{\\|\\}\\~]";
//const WSP$$ = "[\\x20\\x09]";
//const OBS_QTEXT$$ = "[\\x01-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]";  //(%d1-8 / %d11-12 / %d14-31 / %d127)
//const QTEXT$$ = merge("[\\x21\\x23-\\x5B\\x5D-\\x7E]", OBS_QTEXT$$);  //%d33 / %d35-91 / %d93-126 / obs-qtext
//const VCHAR$$ = "[\\x21-\\x7E]";
//const WSP$$ = "[\\x20\\x09]";
//const OBS_QP$ = subexp("\\\\" + merge("[\\x00\\x0D\\x0A]", OBS_QTEXT$$));  //%d0 / CR / LF / obs-qtext
//const FWS$ = subexp(subexp(WSP$$ + "*" + "\\x0D\\x0A") + "?" + WSP$$ + "+");
//const QUOTED_PAIR$ = subexp(subexp("\\\\" + subexp(VCHAR$$ + "|" + WSP$$)) + "|" + OBS_QP$);
//const QUOTED_STRING$ = subexp('\\"' + subexp(FWS$ + "?" + QCONTENT$) + "*" + FWS$ + "?" + '\\"');
const ATEXT$$ = "[A-Za-z0-9\\!\\$\\%\\'\\*\\+\\-\\^\\_\\`\\{\\|\\}\\~]";
const QTEXT$$ = "[\\!\\$\\%\\'\\(\\)\\*\\+\\,\\-\\.0-9\\<\\>A-Z\\x5E-\\x7E]";
const VCHAR$$ = merge(QTEXT$$, "[\\\"\\\\]");
const DOT_ATOM_TEXT$ = subexp(ATEXT$$ + "+" + subexp("\\." + ATEXT$$ + "+") + "*");
const QUOTED_PAIR$ = subexp("\\\\" + VCHAR$$);
const QCONTENT$ = subexp(QTEXT$$ + "|" + QUOTED_PAIR$);
const QUOTED_STRING$ = subexp('\\"' + QCONTENT$ + "*" + '\\"');
//RFC 6068
const DTEXT_NO_OBS$$ = "[\\x21-\\x5A\\x5E-\\x7E]"; //%d33-90 / %d94-126
const SOME_DELIMS$$ = "[\\!\\$\\'\\(\\)\\*\\+\\,\\;\\:\\@]";
const QCHAR$ = subexp(UNRESERVED$$ + "|" + PCT_ENCODED$ + "|" + SOME_DELIMS$$);
const DOMAIN$ = subexp(DOT_ATOM_TEXT$ + "|" + "\\[" + DTEXT_NO_OBS$$ + "*" + "\\]");
const LOCAL_PART$ = subexp(DOT_ATOM_TEXT$ + "|" + QUOTED_STRING$);
const ADDR_SPEC$ = subexp(LOCAL_PART$ + "\\@" + DOMAIN$);
const TO$ = subexp(ADDR_SPEC$ + subexp("\\," + ADDR_SPEC$) + "*");
const HFNAME$ = subexp(QCHAR$ + "*");
const HFVALUE$ = HFNAME$;
const HFIELD$ = subexp(HFNAME$ + "\\=" + HFVALUE$);
const HFIELDS2$ = subexp(HFIELD$ + subexp("\\&" + HFIELD$) + "*");
const HFIELDS$ = subexp("\\?" + HFIELDS2$);
const MAILTO_URI = new RegExp("^mailto\\:" + TO$ + "?" + HFIELDS$ + "?$");
const UNRESERVED = new RegExp(UNRESERVED$$, "g");
const PCT_ENCODED = new RegExp(PCT_ENCODED$, "g");
const NOT_LOCAL_PART = new RegExp(merge("[^]", ATEXT$$, "[\\.]", '[\\"]', VCHAR$$), "g");
const NOT_DOMAIN = new RegExp(merge("[^]", ATEXT$$, "[\\.]", "[\\[]", DTEXT_NO_OBS$$, "[\\]]"), "g");
const NOT_HFNAME = new RegExp(merge("[^]", UNRESERVED$$, SOME_DELIMS$$), "g");
const NOT_HFVALUE = NOT_HFNAME;
const TO = new RegExp("^" + TO$ + "$");
const HFIELDS = new RegExp("^" + HFIELDS2$ + "$");
function decodeUnreserved(str) {
    const decStr = pctDecChars(str);
    return (!decStr.match(UNRESERVED) ? str : decStr);
}
const handler = {
    scheme: "mailto",
    parse: function (components, options) {
        const unEscapeComponent = (str, tryPuny = false) => {
            const result = unescapeComponent(str, options);
            if (tryPuny && options.unicodeSupport) {
                try {
                    return punycode.toASCII(result);
                }
                catch (e) {
                    mailtoComponents.error = mailtoComponents.error || "Email address's domain name can not be converted to ASCII via punycode: " + e;
                    return result;
                }
            }
            return result;
        };
        const { path, query } = components;
        let mailtoComponents = {
            to: [],
        };
        if (path) {
            mailtoComponents = insertInto(mailtoComponents, ['to', path], unEscapeComponent);
            mailtoComponents.path = undefined;
        }
        if (query) {
            mailtoComponents.query = undefined;
            const hFields = query.split("&");
            mailtoComponents = hFields.reduce((acc, hField) => {
                const fragments = hField.split('=');
                return insertInto(mailtoComponents, fragments, unEscapeComponent);
            }, mailtoComponents);
        }
        return Object.assign(components, mailtoComponents);
    },
    serialize: function (mailtoComponents, options) {
        const components = mailtoComponents;
        const to = toArray(mailtoComponents.to);
        if (to) {
            for (let x = 0, xl = to.length; x < xl; ++x) {
                const toAddr = String(to[x]);
                const atIdx = toAddr.lastIndexOf("@");
                const localPart = (toAddr.slice(0, atIdx)).replace(PCT_ENCODED, decodeUnreserved).replace(PCT_ENCODED, toUpperCase).replace(NOT_LOCAL_PART, pctEncChar);
                let domain = toAddr.slice(atIdx + 1);
                //convert IDN via punycode
                try {
                    domain = (!options.iri ? punycode.toASCII(unescapeComponent(domain, options).toLowerCase()) : punycode.toUnicode(domain));
                }
                catch (e) {
                    components.error = components.error || "Email address's domain name can not be converted to " + (!options.iri ? "ASCII" : "Unicode") + " via punycode: " + e;
                }
                to[x] = localPart + "@" + domain;
            }
            components.path = to.join(",");
        }
        const headers = mailtoComponents.headers = mailtoComponents.headers || {};
        if (mailtoComponents.subject)
            headers["subject"] = mailtoComponents.subject;
        if (mailtoComponents.body)
            headers["body"] = mailtoComponents.body;
        const fields = [];
        for (const name in headers) {
            if (headers[name] !== O[name]) {
                fields.push(name.replace(PCT_ENCODED, decodeUnreserved).replace(PCT_ENCODED, toUpperCase).replace(NOT_HFNAME, pctEncChar) +
                    "=" +
                    headers[name].replace(PCT_ENCODED, decodeUnreserved).replace(PCT_ENCODED, toUpperCase).replace(NOT_HFVALUE, pctEncChar));
            }
        }
        if (fields.length) {
            components.query = fields.join("&");
        }
        return components;
    }
};
export default handler;
function insertInto(components, fragment, unEscapeComponent) {
    const [prop, value] = fragment;
    if (['subject', 'body'].includes(prop)) {
        return Object.assign(components, { [prop]: unEscapeComponent(value) });
    }
    if (prop === 'to') {
        const addresses = value
            .split(',')
            .map((address) => {
            const [local, domain] = address.split('@');
            const unescapedLocal = unEscapeComponent(local);
            const unescapedDomain = unEscapeComponent(domain, true);
            return `${unescapedLocal}@${unescapedDomain.toLowerCase()}`;
        });
        return Object.assign(components, { to: components.to.concat(addresses) });
    }
    const headers = Object.assign({}, components.headers, { [unEscapeComponent(prop)]: unEscapeComponent(value) });
    return Object.assign(components, { headers });
}
//# sourceMappingURL=mailto.js.map