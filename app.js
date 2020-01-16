var _ = require('lodash');
var nacl = require('tweetnacl');
const util = require('util');


/*
c /home/kai/projects/19.12.27_public/
node app


*/



const fromHexString = hexString =>
  new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
const toHexString = bytes =>
  bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');



var randHex = function(len) {
  var maxlen = 8,
      min = Math.pow(16,Math.min(len,maxlen)-1) 
      max = Math.pow(16,Math.min(len,maxlen)) - 1,
      n   = Math.floor( Math.random() * (max-min+1) ) + min,
      r   = n.toString(16);
  while ( r.length < len ) {
     r = r + randHex( len - maxlen );
  }
  return r;
};


var _titleIndex = {};
function makeByTitle(title)
{
  if(title instanceof Node) return title;
  var node = _titleIndex[title];
  if(node) return node;
  return _titleIndex[title] = Node.make();
}
function getByTitle(title)
{
  return _titleIndex[title];
}

var AllNodes = {};
class Node
{
  constructor(hex)
  {
    this.hex = hex || randHex(8);
  }
  fromType_claims(type)
  {
    if(!type) return [];
    if(!(type instanceof Node)) type = makeByTitle(type);
    var typeTos = Claim.fromTypeToIndex[this.hex];
    if(!typeTos) return [];
    return typeTos[type.hex] || [];
  }
  fromType_to(type)
  {
    var claims = this.fromType_claims(type);
    // console.log("Node.fromType_to","claims",claims);
    return claims.length > 0 ? claims[0][2] : undefined;
  }
  fromType_tos(type)
  {
    var claims = this.fromType_claims(type);
    return claims.map(claim=>claim[2]);
  }
  fromType_toStr(type)
  {
    var to = this.fromType_to(type);
    return to && to.s ? to.s : undefined;
  }
  fromType_tosStr(type)
  {
    var tos = this.fromType_tos(type);
    tos = tos.map(to=>to && to.s ? to.s : undefined).filter(to=>to);
    return tos;
  }

  toType_claims(type)
  {
    if(!type) return [];
    if(!(type instanceof Node)) type = makeByTitle(type);
    var typeFroms = Claim.toTypeFromIndex[this.hex];
    if(!typeFroms) return [];
    return typeFroms[type.hex] || [];
  }
  toType_from(type)
  {
    var claims = this.toType_claims(type);
    // console.log("Node.fromType_to","claims",claims);
    return claims.length > 0 ? claims[0][0] : undefined;
  }
  toType_froms(type)
  {
    var claims = this.toType_claims(type);
    return claims.map(claim=>claim[0]);
  }

  executeJsMethod(type)
  {
    var instanciables = this.fromType_tos(_instanceOf);
    instanciables.push(_object);

    for(var i=0;i<instanciables.length;i++)
    {
      var instanciable = instanciables[i];
      var jsMethodString = instanciable.fromType_toStr(type);
      if(jsMethodString)
        return eval(jsMethodString) (this);
    }
    return results;
  }
  executeJsMethods(type)
  {
    var instanciables = this.fromType_tos(_instanceOf);
    instanciables.push(_object);
    var results = [];
    instanciables.forEach(instanciable=>
    {
      var jsMethodStrings = instanciable.fromType_tosStr(type);
      jsMethodStrings.forEach(jsMethodString=>
      {
        var method=eval(jsMethodString);
        results.push(method(this));
      });
    });
    return results;
  }

};
Node.make = function(hex)
{
  if(!hex) hex = randHex(8);
  if(AllNodes[hex]) return AllNodes[hex];
  return AllNodes[hex] = new Node(hex);
}
Node.get = hex => AllNodes[hex];

class ClaimClass
{
  constructor()
  {
    this.claims = [];
    this.fromTypeToIndex = {};
    this.toTypeFromIndex = {};
  }

  setDefaultSigningKey(privateKey)
  {
    this.keyPair = nacl.sign.keyPair.fromSecretKey(fromHexString(privateKey));
    this.privateKey = toHexString(this.keyPair.secretKey);
    this.publicKey = toHexString(this.keyPair.publicKey);
    console.log("ClaimClass.setDefaultSigningKey()","publicKey",this.publicKey);
  }
  setDefaultUser(user)
  {
    this.user = user;
  }

  make(_from,_type,___to)
  {
    // if(_from instanceof Node) _from = _from.hex;
    // if(_type instanceof Node) _type = _type.hex;
    // if(___to instanceof Node) ___to = ___to.hex;

    var toIsNode = ___to instanceof Node;

    var date = new Date();

    var stringToSign = _from.hex+","+_type.hex+","+date.valueOf()+"/";
    stringToSign+= toIsNode ? ___to.hex : ___to.s;
    var stringToSignBytes = new util.TextEncoder("utf-8").encode(stringToSign);

    var signatureBytes = nacl.sign.detached(stringToSignBytes, this.keyPair.secretKey)
    var signatureHex = toHexString(signatureBytes);
    // console.log("ClaimClass.make()",stringToSign ,"signature",signatureHex);
    var claim = [_from,_type,___to,date,this.user,signatureHex];

    // console.log(nacl.sign.detached.verify(stringToSignBytes,fromHexString(signatureHex),fromHexString(this.publicKey)));
    // console.log(claim);

    var _typeTo__ = this.fromTypeToIndex[_from.hex];
    if(!_typeTo__) _typeTo__ = this.fromTypeToIndex[_from.hex] = {};
    var _to__ = _typeTo__[_type.hex];
    if(!_to__) _to__ = _typeTo__[_type.hex] = [];
    _to__.push(claim);

    if(toIsNode)
    {
      var _typeFrom = this.toTypeFromIndex[___to.hex];
      if(!_typeFrom) _typeFrom = this.toTypeFromIndex[___to.hex] = {};
      var _from = _typeFrom[_type.hex];
      if(!_from) _from = _typeFrom[_type.hex] = [];
      _from.push(claim);
    }

    this.claims.push(claim);
    // console.log(claim[4],claim[3],claim[0],claim[1],claim[2]);
    return claim;
  }
};
const Claim = new ClaimClass();
Claim.isString = value=> value instanceof Object && value.s;
Claim.isNode = value=> value instanceof Node;
var keyPair = nacl.sign.keyPair();
const _Kai =  makeByTitle("Kai Elvin");
Claim.setDefaultSigningKey(toHexString(keyPair.secretKey));
Claim.setDefaultUser(_Kai);
Object.freeze(Claim);


const _object =  makeByTitle("object");
const _instanceOf =  makeByTitle("instanceOf");
const _title =  makeByTitle("title");
const _inCategory =  makeByTitle("inCategory");
const _coreObjects =  makeByTitle("coreObjects");

// function makeClaim(_from,_type,___to)
// {
//   if(typeof(_from) === "string") _from = makeByTitle(_from);
//   if(typeof(_type) === "string") _type = makeByTitle(_type);
//   if(typeof(___to) === "string") ___to = makeByTitle(___to);
//   Claim.make(_from,_type,___to);
// }

function createObject(typeTos={})
{
  var node = typeTos.title ? makeByTitle(typeTos.title.s) : Node.make();
  for(var typeTitle in typeTos)
  {
    var addOneTo = to=>
    {
      to = Claim.isNode(to) ? to
         : Claim.isString(to) ? to
         : makeByTitle(to);
      Claim.make( node, makeByTitle(typeTitle), to );
    }
    var to = typeTos[typeTitle];
    if(Array.isArray(to)) to.forEach(addOneTo);
    else addOneTo(to);
  }

  return node;
}

createObject(
{
  title:{s:"title"},
  instanceOf:"claimType",
  inCategory:"coreObjects",
});


createObject(
{
  title:{s:"object"},
  instanceOf:"instanciable",
  inCategory:"coreObjects",
  htmlLink: {s:String(node=>
  {
    var title = node.fromType_toStr(_title) || node.hex;
    var url = !title || title.length > 25 ? node.hex : title;
    return '<a href="http://localhost:3000/'+url+'">'+title+'</a>';
  })},
  htmlViewElement: [
    {s:String(node=>
    {
      var instanciables = node.fromType_tos(_instanceOf);
      instanciables.push(_object);
      console.log(instanciables);
      var fromTypes = _.flatten(instanciables.map(instanciable=>instanciable.toType_froms("typeFrom")));
      return '<h2>Attributes</h2>'
        +'<ul>'
          +fromTypes.map(type=>
          {
            var values = node.fromType_tos(type);
            var isStrings = values.some(Claim.isString);
            console.log("values",values);
            // var valuesHtml = values.map(value=>
            //     Claim.isString(value)
            //     ? '<textarea>'+value+'</textarea>'
            //     : value.executeJsMethod("htmlLink")
            //   )
            //   .join(isStrings?"<br>":", ");

            var valuesHtml = "";

            return '<li>'
              +type.executeJsMethod("htmlLink")
              +" > "
              +valuesHtml
            +'</li>'
          }).join('')
        +'</ul>';
    })},
  ],
});
createObject(
{
  title:{s:"instanciable"},
  instanceOf:"instanciable",
  inCategory:"coreObjects",
  htmlViewElement: [
    {s:String(node=>
    {
      var subnodes = node.toType_froms(_instanceOf);
      return '<h2>Instances:</h2><ul>'+
          subnodes.map(subnode=>'<li>'+subnode.executeJsMethod("htmlLink")+'</li>').join('')+'</ul>';
    })},
    {s:String(node=>
    {
      return '<form action="/createObject" method="post">'
          +'<input type="hidden" name="instanceOf" value="'+node.hex+'" />'
          +'<button type="submit">New object</button>'
        +'</form>';
    })},
  ],

});
createObject(
{
  title:{s:"instanceOf"},
  instanceOf:"claimType",
  typeTo:"instanciable",
  inCategory:"coreObjects",
});
createObject(
{
  title:{s:"htmlViewElement"},
  instanceOf:"claimType",
  typeFrom:"instanciable",
  inCategory:"coreObjects",
});
createObject(
{
  title:{s:"htmlLink"},
  instanceOf:"claimType",
  typeFrom:"instanciable",
  inCategory:"coreObjects",
});


createObject(
{
  title:{s:"claimType"},
  instanceOf:"instanciable",
  inCategory:"coreObjects",
});
createObject(
{
  title:{s:"typeFrom"},
  instanceOf:"claimType",
  typeFrom:"claimType",
  typeTo:"instanciable",
  inCategory:"coreObjects",
});
createObject(
{
  title:{s:"typeTo"},
  instanceOf:"claimType",
  typeFrom:"claimType",
  typeTo:"instanciable",
  inCategory:"coreObjects",
});


createObject(
{
  title:{s:"objectCategory"},
  instanceOf:"instanciable",
  inCategory:"coreObjects",
  htmlViewElement: {s:String(node=>
  {
    var subnodes = node.toType_froms(_inCategory);
    return '<h2>Objects in the caterogy:</h2><ul>'+
        subnodes.map(subnode=>'<li>'+subnode.executeJsMethod("htmlLink")+'</li>').join('')+'</ul>';
  })},
});
createObject(
{
  title:{s:"coreObjects"},
  instanceOf:"objectCategory",
  inCategory:"coreObjects",
});
createObject(
{
  title:{s:"inCategory"},
  instanceOf:"claimType",
  typeTo:"objectCategory",
  inCategory:"coreObjects",
});


createObject(
{
  title:{s:"person"},
  instanceOf:"instanciable",
  inCategory:"coreObjects",
});
createObject(
{
  title:{s:"publicKey"},
  instanceOf:"claimType",
  inCategory:"coreObjects",
});


createObject(
{
  title:{s:"Kai Elvin"},
  instanceOf:"person",
  publicKey:toHexString(keyPair.publicKey),
});


createObject(
{
  title:{s:"big talk question"},
  instanceOf:"instanciable",
});
const lineReader = require('line-reader');
lineReader.eachLine('./data/bigTalkQuestions.txt', function(line)
{
  createObject(
  {
    title:{s:line},
    instanceOf:"big talk question",
  });
});





function show(node)
{
  var instanciable = node.fromType_to(_instanceOf);
  var title = node.fromType_toStr(_title);
  var instanciableTitle = instanciable && instanciable.fromType_toStr(_title);
  instanciableTitle = instanciableTitle ? "instanceof("+instanciableTitle+")" : "";
  console.log(node.hex, title, instanciableTitle);
}

_.values(AllNodes).forEach(show);


// function _object_link(node)
// {
//   var title = node.fromType_to(_title);
//   return '<a href="http://localhost:3000/'+(title||node.hex)+'">'+title+'</a>';
// }

/*

Represent:
* people
* belief of duplicate (same person, same music but different video clip, same article but different website)
* articles
* memetic beliefs, like "you have no idea what you are talking about", which can be associated to internet memes (images) and to articles, talks or comments
* dare using vague claim types (open to interpretation)
* big talk questions with tags (easy way of making a demo app)

*/





const express = require('express')
const app = express()
const port = 3000
var bodyParser = require('body-parser');
app.use( bodyParser.json({limit: '50mb'}) );       // to support JSON-encoded bodies
app.use(bodyParser.urlencoded({     // to support URL-encoded bodies
  extended: true
}));
app.get('/', (req, res) => res.send('Hello World!'))

app.get('/:id', (req, res) =>
{
  var node = Node.get(req.params.id) || getByTitle(req.params.id);
  if(!node) res.status(404).send("404: unknown object");
  var html = "<h1>"+(node.fromType_toStr(_title)||node.hex)+"</h1>";

  var instanciable = node.fromType_to(_instanceOf);
  if(instanciable) html+= '<p>Instance of: '+instanciable.executeJsMethod("htmlLink")+'</p>';

  html+= node.executeJsMethods("htmlViewElement").join("");

  res.send(html);
});

app.post('/createObject', (req, res) =>
{
  var node = createObject(
  {
    instanceOf:Node.make(req.body.instanceOf),
  });

    res.redirect('/'+node.hex);
});


app.listen(port, () => console.log(`Example app listening on port ${port}!`))

console.log("http://localhost:3000/"+makeByTitle("instanciable").hex);