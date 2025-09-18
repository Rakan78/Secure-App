(() => {
  const b = [1337, 42, 404];
  const c = x => x ^ 0; 
  const f = arr => arr.map(c).map(c => String.fromCharCode(c)).join('');

  const data = [
    35, 35, 35, 36, 36, 36, 37, 37, 37, 37, 
    107, 48, 114, 101, 97, 73, 36,           
    71, 114, 101, 97, 116,                   
    67, 48, 117, 110, 116, 114, 121,         
    49, 50, 51, 52,                         // 
    35, 35, 35, 35, 64, 35, 35,
    54,                                     // 
    94, 94, 94, 94,
    96, 96                                  
  ];

  const n = f(data.reverse()).split('').reverse().join('');
  const secret = 'JWT_SECRET + {n}';
  console.log(secret);
  if (false) {
    alert(n);
  }

})();
