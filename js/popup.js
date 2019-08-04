/* global Ont angular localStorage chrome aesjs */

const app = angular.module('mainpopup', []).config([
  '$compileProvider', ($compileProvider) => {
    $compileProvider.imgSrcSanitizationWhitelist(/^\s*(https?|local|data|chrome-extension):/);
  },
]);

const {
  Crypto,
  Parameter,
  ParameterType,
  TransactionBuilder,
  RpcClient,
  utils,
} = Ont;

const {
  Address,
  PrivateKey,
} = Crypto;

const {
  ByteArray,
} = ParameterType;

const client = new RpcClient('http://localhost:20336');

// var passwords = {};

function fixMaster(master) {
  let rn = master;
  if (rn.length > 16) {
    return 'INVALID';
  }
  while (rn.length < 16) {
    rn += 'a';
  }
  return rn;
}

function removeDuplicatesSafe(arr) {
  const seen = {};
  const retArr = [];
  for (let i = 0; i < arr.length; i += 1) {
    const string = JSON.stringify(arr[i]);
    if (!(string in seen)) {
      retArr.push(arr[i]);
      seen[string] = true;
    }
  }
  return retArr;
}

function addhttp(url) {
  let xurl = url;
  if (!/^(f|ht)tps?:\/\//i.test(xurl)) {
    xurl = `http://${xurl}`;
  }
  return xurl;
}

app.controller('popupCtrl', ($scope /* , $http, $window */) => {
  $scope.isLoggedIn = localStorage.getItem('isLoggedIn');
  $scope.addOrEdit = 'Add a password';
  $scope.showDetails = false;
  $scope.showPasswords = false;
  $scope.firstLoad = true;
  $scope.showAddPassword = false;
  $scope.showError = false;

  if ($scope.isLoggedIn) {
    const key = localStorage.getItem('pk');
    const master = localStorage.getItem('master');
    $scope.getPasswords(key, master).then((res) => {
      if (res == null) {
        $scope.isLoggedIn = false;
        localStorage.setItem('isLoggedIn', false);
      } else {
        $scope.showDetails = false;
        $scope.showPasswords = true;
        $scope.showAddPassword = false;
        $scope.showDetails = false;
        $scope.firstLoad = false;
      }
    });
  }

  $scope.selectedPassword = {};

  $scope.logInClicked = () => {
    const pk = document.getElementById('private-key-input').value;
    const pw = document.getElementById('password-input').value;
    $scope.isValidPrivateKey(pk, pw, (valid) => {
      if (valid) {
        $scope.logIn();
        localStorage.setItem('isLoggedIn', true);
      } else {
        $scope.showError = true;
      }
    });
  };

  $scope.get = (pkey, handler) => {
    const privateKey = new PrivateKey(pkey);
    const publicKey = privateKey.getPublicKey();
    const user = Address.fromPubKey(publicKey);

    const p1 = new Parameter('user', ByteArray, user.serialize());
    const functionName = 'get';
    const contractAddr = new Address(utils.reverseHex('c168e0fb1a2bddcd385ad013c2c98358eca5d4dc'));
    const gasPrice = '0';
    const gasLimit = '20000';
    const tx = TransactionBuilder.makeInvokeTransaction(functionName, [p1], contractAddr, gasPrice, gasLimit, user);
    TransactionBuilder.signTransaction(tx, privateKey);

    client.sendRawTransaction(tx.serialize(), true).then((res) => {
      handler(res.result.Result);
    });
  };

  $scope.put = (pkey, value, handler) => {
    const privateKey = new PrivateKey(pkey);
    const publicKey = privateKey.getPublicKey();
    const user = Address.fromPubKey(publicKey);

    const p1 = new Parameter('user', ByteArray, user.serialize());
    const p2 = new Parameter('value', String, value);
    const functionName = 'put';
    const contractAddr = new Address(utils.reverseHex('c168e0fb1a2bddcd385ad013c2c98358eca5d4dc'));
    const gasPrice = '0';
    const gasLimit = '20000';
    const tx = TransactionBuilder.makeInvokeTransaction(functionName, [p1, p2], contractAddr, gasPrice, gasLimit, user);
    TransactionBuilder.signTransaction(tx, privateKey);

    client.sendRawTransaction(tx.serialize(), false).then((res) => {
      handler(res);
    });
  };

  $scope.getPasswords = (privateKey, master) => { // eslint-disable-line
    return new Promise((resolve) => {
      $scope.get(privateKey, (data) => {
        if (data === '00') {
          resolve([]);
        } else {
          const crypt = aesjs.utils.utf8.toBytes(master);
          const encryptedBytes = aesjs.utils.hex.toBytes(data);
          const aesCtr = new aesjs.ModeOfOperation.ctr(crypt); // eslint-disable-line
          const decryptedBytes = aesCtr.decrypt(encryptedBytes);
          const decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);
          try {
            const arr = JSON.parse(decryptedText);
            const fix = removeDuplicatesSafe(arr);
            console.log(JSON.stringify(fix));
            resolve(fix);
          } catch (error) {
            console.log(error);
            resolve(null);
          }
        }
      });
    });
  };

  $scope.encryptAndSerialize = (privateKey, master, dict, handler) => {
    const str = JSON.stringify(dict);
    const crypt = aesjs.utils.utf8.toBytes(master);
    const textBytes = aesjs.utils.utf8.toBytes(str);
    const aesCtr = new aesjs.ModeOfOperation.ctr(crypt); // eslint-disable-line
    const encryptedBytes = aesCtr.encrypt(textBytes);
    const value = aesjs.utils.hex.fromBytes(encryptedBytes);
    $scope.put(privateKey, value, handler);
  };

  $scope.addPassword = () => {
    $scope.addOrEdit = 'Add a password';
    document.getElementById('new-username').value = '';
    document.getElementById('new-url').value = '';
    document.getElementById('new-password').value = '';

    $scope.showAddPassword = true;
    $scope.showDetails = false;
    $scope.showPasswords = false;
    $scope.firstLoad = false;
  };

  $scope.deletePassword = () => {
    const pass = localStorage.getItem('pass');
    const array = $scope.passwords;

    const { length } = array;
    for (let i = 0; i < length; i += 1) {
      const current = JSON.stringify(array[i]);
      console.log(current);
      if (current === pass) {
        array.splice(i, 1);
        break;
      }
    }

    $scope.passwords = array;
    $scope.close();

    const pk = localStorage.getItem('pk');
    const master = localStorage.getItem('master');

    $scope.encryptAndSerialize(pk, master, $scope.passwords, (set) => {
      const success = set.desc === 'SUCCESS';
      console.log(`Success: ${success}`);
    });
  };

  $scope.editPassword = () => {
    $scope.addOrEdit = 'Edit a password';
    $scope.showAddPassword = true;
    $scope.showDetails = false;
    $scope.showPasswords = false;
    $scope.firstLoad = false;

    const pass = localStorage.getItem('pass');
    const parsed = JSON.parse(pass);
    const un = parsed.username;
    const pw = parsed.password;
    const { url } = parsed;

    document.getElementById('new-username').value = un;
    document.getElementById('new-url').value = url;
    document.getElementById('new-password').value = pw;
  };

  $scope.close = () => {
    $scope.showDetails = false;
    $scope.showPasswords = true;
    $scope.showAddPassword = false;
    $scope.showDetails = false;
    $scope.firstLoad = false;
  };

  $scope.addNewPassword = () => {
    const un = document.getElementById('new-username').value;
    const url = document.getElementById('new-url').value;
    const pw = document.getElementById('new-password').value;

    if ((un === '' || un == null) || (url === '' || url == null) || (pw === '' || pw == null)) {
      $scope.showAddPassword = false;
      $scope.showDetails = false;
      $scope.showPasswords = true;
      $scope.firstLoad = false;
      return;
    }

    const pk = localStorage.getItem('pk');
    const master = localStorage.getItem('master');

    const newPassword = {
      password: pw,
      username: un,
      url,
    };

    if (!$scope.passwords.includes(newPassword)) {
      $scope.passwords.push(newPassword);
    }

    $scope.close();

    $scope.encryptAndSerialize(pk, master, $scope.passwords, (set) => {
      const success = set.desc === 'SUCCESS';
      console.log(`Success: ${success}`);
    });
  };

  $scope.isValidPrivateKey = async (key, pw, handler) => {
    const master = fixMaster(pw);
    const res = await $scope.getPasswords(key, master);
    if (res == null) {
      console.log('Incorrect password/privatekey combination');
      handler(false);
    } else {
      localStorage.setItem('pk', key);
      localStorage.setItem('master', master);
      $scope.passwords = res;
      $scope.encryptAndSerialize(key, master, res, (set) => {
        console.log(set.desc === 'SUCCESS');
        handler(true);
      });
    }
  };

  $scope.logIn = () => {
    $scope.firstLoad = false;
    $scope.showPasswords = true;
  };

  $scope.backPressed = () => {
    $scope.showDetails = false;
    $scope.showPasswords = true;
    $scope.showAddPassword = false;
    $scope.showDetails = false;
    $scope.firstLoad = false;
  };

  $scope.showDetailsForPassword = (pass) => {
    const pw = JSON.stringify(pass);
    localStorage.setItem('pass', pw);
    $scope.showDetails = true;
    $scope.showPasswords = false;
  };

  $scope.action = (pass, arg) => {
    const pw = localStorage.getItem('pass');
    const parsed = JSON.parse(pw);
    const {
      username,
      password,
      url,
    } = parsed;

    if (arg === 1) {
      // Copy Username
      const input = document.getElementById('copyfrom');
      input.value = username;
      input.select();
      document.execCommand('copy');
      console.log(username);
    } else if (arg === 2) {
      // Copy Password
      const input = document.getElementById('copyfrom');
      input.value = password;
      input.select();
      document.execCommand('copy');
      console.log(password);
    } else if (arg === 3) {
      // Copy URL
      const input = document.getElementById('copyfrom');
      input.value = url;
      input.select();
      document.execCommand('copy');
      console.log(url);
    } else if (arg === 4) {
      // Go to URL
      const newUrl = addhttp(url);
      chrome.tabs.update({
        url: newUrl,
      });
    } else if (arg === 5) {
      // Edit
      $scope.editPassword();
    } else if (arg === 6) {
      // Delete
      $scope.deletePassword();
    }
  };
});
