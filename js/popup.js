/* global Ont angular localStorage chrome CryptoJS */

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
  ScriptBuilder,
} = Ont;

const {
  Address,
  PrivateKey,
} = Crypto;

const {
  ByteArray,
} = ParameterType;

const client = new RpcClient('http://localhost:20336');
const contractHash = 'c168e0fb1a2bddcd385ad013c2c98358eca5d4dc';

function addhttp(url) {
  let xurl = url;
  if (!/^(f|ht)tps?:\/\//i.test(xurl)) {
    xurl = `http://${xurl}`;
  }
  return xurl;
}

function padPassword(password) {
  let pw = password;
  let size = 0;
  const { length } = pw;
  if (length < 16) {
    size = 16;
  } else if (length < 24) {
    size = 24;
  } else if (length < 32) {
    size = 32;
  }

  const difference = size - length;
  for (let i = 0; i < difference; i += 1) {
    pw = `${pw}A`;
  }
  return pw;
}

function decryptString(string, password) {
  const bytes = CryptoJS.AES.decrypt(string, password);
  const originalText = bytes.toString(CryptoJS.enc.Utf8);
  return originalText;
}

function encryptString(string, password) {
  return CryptoJS.AES.encrypt(string, password).toString();
}

function getEncryptedKey(privateKey, password) {
  return encryptString(privateKey.key, password);
}

function get(privateKey) {
  return new Promise((resolve, reject) => {
    const publicKey = privateKey.getPublicKey();
    const user = Address.fromPubKey(publicKey);

    const p1 = new Parameter('user', ByteArray, user.serialize());
    const functionName = 'getAll';
    const contractAddr = new Address(utils.reverseHex(contractHash));
    const gasPrice = '0';
    const gasLimit = '20000';
    const tx = TransactionBuilder.makeInvokeTransaction(functionName, [p1], contractAddr, gasPrice, gasLimit, user);
    TransactionBuilder.signTransaction(tx, privateKey);

    client.sendRawTransaction(tx.serialize(), true)
      .then((res) => {
        resolve(res.result.Result);
      })
      .catch((error) => {
        reject(error);
      });
  });
}

function put(pkey, website, username, password) {
  return new Promise((resolve, reject) => {
    const privateKey = new PrivateKey(pkey);
    const publicKey = privateKey.getPublicKey();
    const user = Address.fromPubKey(publicKey);

    const encWebsite = encryptString(website, privateKey.key);
    const encUsername = encryptString(username, privateKey.key);
    const encPassword = encryptString(password, privateKey.key);

    const p1 = new Parameter('address', ByteArray, user.serialize());
    const p2 = new Parameter('website', String, encWebsite);
    const p3 = new Parameter('username', String, encUsername);
    const p4 = new Parameter('password', String, encPassword);

    const functionName = 'put';
    const contractAddr = new Address(utils.reverseHex('c168e0fb1a2bddcd385ad013c2c98358eca5d4dc'));
    const gasPrice = '500';
    const gasLimit = '20000';
    const args = [p1, p2, p3, p4];
    const tx = TransactionBuilder.makeInvokeTransaction(functionName, args, contractAddr, gasPrice, gasLimit, user);
    TransactionBuilder.signTransaction(tx, privateKey);

    client.sendRawTransaction(tx.serialize(), false)
      .then((res) => {
        resolve(res.result.Result);
      })
      .catch((error) => {
        reject(error);
      });
  });
}

function parseData(dct, hexPrivateKey) {
  const passwords = [];
  const keys = Object.keys(dct);
  const count = keys.length;
  for (let i = 0; i < count; i += 1) {
    const key = keys[i];
    const url = decryptString(key, hexPrivateKey);
    const value = dct[key];
    const username = decryptString(value.username, hexPrivateKey);
    const password = decryptString(value.password, hexPrivateKey);
    const entry = {
      url,
      username,
      password,
    };
    passwords.push(entry);
  }
  return passwords;
}

function getUserData(privateKey) {
  return new Promise((resolve, reject) => {
    get(privateKey)
      .then((data) => {
        if (data === '00') {
          resolve([]);
        } else {
          const val = ScriptBuilder.deserializeItem(data);
          const parsed = parseData(val, privateKey.key);
          resolve(parsed);
        }
      })
      .catch((error) => {
        reject(error);
      });
  });
}

function privateKeyFromWif(wif, handler) {
  try {
    const privateKey = PrivateKey.deserializeWIF(wif);
    handler(privateKey);
  } catch (error) {
    console.log(error);
    handler(null);
  }
}

app.controller('popupCtrl', ($scope /* , $http, $window */) => {
  $scope.addOrEdit = 'Add a password';
  $scope.showDetails = false;
  $scope.showPasswords = false;
  $scope.firstLoad = true;
  $scope.showAddPassword = false;
  $scope.showError = false;
  $scope.errorMessage = '';
  $scope.selected = {};

  $scope.logInClicked = () => {
    const wif = document.getElementById('wif-key-input').value;
    const password = document.getElementById('password-input').value;
    const confirm = document.getElementById('confirm-password-input').value;
    if (wif.length < 52) {
      $scope.errorMessage = 'Error signing in, invalid length WIF';
      $scope.showError = true;
    } else if (password.length < 3) {
      $scope.errorMessage = 'Error signing in, password must be longer than 3 characters';
      $scope.showError = true;
    } else if (password.length > 32) {
      $scope.errorMessage = 'Error signing in, password must be shorter than 33 characters';
      $scope.showError = true;
    } else if (password !== confirm) {
      $scope.errorMessage = 'Error signing in, passwords do not match';
      $scope.showError = true;
    } else {
      privateKeyFromWif(wif, (privateKey) => {
        if (privateKey != null) {
          $scope.errorMessage = '';
          $scope.showError = false;

          const padded = padPassword(password);
          const encryptedKey = getEncryptedKey(privateKey, padded);
          localStorage.setItem('encryptedKey', encryptedKey);

          getUserData(privateKey)
            .then((items) => {
              console.log(`Loaded ${items.length} passwords`);
              $scope.passwords = items;
              $scope.logIn();
            })
            .catch((error) => {
              console.error(error);
              $scope.passwords = [];
              $scope.logIn();
            });
        } else {
          $scope.errorMessage = 'Error signing in, invalid WIF';
          $scope.showError = true;
        }
      });
    }
  };

  $scope.logIn = () => {
    $scope.firstLoad = false;
    $scope.showPasswords = true;
  };

  $scope.showDetailsForPassword = (item) => {
    $scope.selected = item;
    $scope.showDetails = true;
    $scope.showPasswords = false;
  };

  $scope.action = (arg) => {
    const item = $scope.selected;
    const {
      url,
      username,
      password,
    } = item;

    if (arg === 1) {
      // Copy Username
      const input = document.getElementById('copyfrom');
      input.value = username;
      input.select();
      document.execCommand('copy');
    } else if (arg === 2) {
      // Copy Password
      const input = document.getElementById('copyfrom');
      input.value = password;
      input.select();
      document.execCommand('copy');
    } else if (arg === 3) {
      // Copy URL
      const input = document.getElementById('copyfrom');
      input.value = url;
      input.select();
      document.execCommand('copy');
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

  $scope.addPassword = () => {
    $scope.addOrEdit = 'Add a password';
    document.getElementById('new-username').value = '';
    document.getElementById('new-url').value = '';
    document.getElementById('new-password').value = '';
    document.getElementById('master-password').value = '';

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

    // const pk = localStorage.getItem('pk');
    // const master = localStorage.getItem('master');
    //
    // $scope.encryptAndSerialize(pk, master, $scope.passwords, (set) => {
    //   const success = set.desc === 'SUCCESS';
    //   console.log(`Success: ${success}`);
    // });
  };

  $scope.editPassword = () => {
    $scope.addOrEdit = 'Edit a password';
    $scope.showAddPassword = true;
    $scope.showDetails = false;
    $scope.showPasswords = false;
    $scope.firstLoad = false;

    const item = $scope.selected;
    const {
      url,
      username,
      password,
    } = item;

    document.getElementById('new-username').value = username;
    document.getElementById('new-url').value = url;
    document.getElementById('new-password').value = password;
  };

  $scope.close = () => {
    $scope.showDetails = false;
    $scope.showPasswords = true;
    $scope.showAddPassword = false;
    $scope.showDetails = false;
    $scope.firstLoad = false;
  };

  $scope.addNewPassword = () => {
    const username = document.getElementById('new-username').value;
    const website = document.getElementById('new-url').value;
    const password = document.getElementById('new-password').value;
    const passcode = document.getElementById('master-password').value;

    if ((username === '' || username == null) || (website === '' || website == null) || (password === '' || password == null)) {
      $scope.showAddPassword = false;
      $scope.showDetails = false;
      $scope.showPasswords = true;
      $scope.firstLoad = false;
      return;
    }

    $scope.close();

    const padded = padPassword(passcode);
    const encryptedKey = localStorage.getItem('encryptedKey');
    const privateKey = decryptString(encryptedKey, padded);

    put(privateKey, website, username, password)
      .then((res) => {
        const success = res.desc === 'SUCCESS';
        console.log(`Success: ${success}`);
      })
      .catch((error) => {
        console.log(error);
      });
  };

  $scope.backPressed = () => {
    $scope.showDetails = false;
    $scope.showPasswords = true;
    $scope.showAddPassword = false;
    $scope.showDetails = false;
    $scope.firstLoad = false;
    $scope.selected = {};
  };
});
