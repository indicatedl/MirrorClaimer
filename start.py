import requests
import json
import os
import secrets
import base64
import concurrent.futures
from time import time, sleep
from sys import stderr, exit
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from datetime import datetime

import ua_generator
from web3 import Web3
from loguru import logger
from eth_account.messages import encode_defunct
from dotenv import dotenv_values

from modules.emailimap import emailImap
from modules.emailimap import TimeoutError

# FILE SETTINGS
file_wallets = 'files/wallets.txt'
file_proxies = 'files/proxies.txt'
file_registered = 'files/registered.txt'
file_dismissed_emails = 'files/dismissed_emails.txt'
file_mails = 'files/mails.txt'
file_log = 'logs/log.log'

# SETTINGS
ENV = dotenv_values('.env')
URL_LINK = ENV['URL']
NFT_CONTRACT_ADDRESS = ENV['NFT_CONTRACT_ADDRESS']
MINT_TYPE = ENV['TYPE']
VALUE = float(ENV['PRICE'])
THREADS = int(ENV['THREADS'])
CLAIMED_FILE = 'files/' + ENV['FILE']
WEB3_PROVIDER = ENV['WEB3_PROVIDER']
CHAIN_ID = int(ENV['CHAIN_ID']) 
IMAP_FOLDER = ENV['IMAP_FOLDER']
IMAP_SERVER = ENV['IMAP_SERVER']
FIRST_ENTRY_STATUS = ENV['FIRST_ENTRY']

# LOGGING SETTING
logger.remove()
logger.add(stderr, format="<white>{time:HH:mm:ss}</white> | <level>{level: <8}</level> | <cyan>{line}</cyan> - <white>{message}</white>")
logger.add(file_log, format="<white>{time:HH:mm:ss}</white> | <level>{level: <8}</level> | <cyan>{line}</cyan> - <white>{message}</white>")


def setup_session(proxy):
    session = requests.Session()
    ua = ua_generator.generate(device='desktop', browser='chrome')
    headers = {
            'accept': '*/*',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'pl-PL,pl;q=0.9,en-US;q=0.8,en;q=0.7',
            'cache-control': 'no-cache',
            'content-type': 'application/json;charset=UTF-8',
            'origin': url,
            'referer': f'{url}/',
            'sec-ch-ua': f'"{ua.ch.brands[2:]}"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': f'"{ua.platform.title()}"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'token': 'undefined',
            'user-agent': ua.text,
            }
    session.headers = headers
    session.proxies.update({'https': 'http://' + proxy})
    return session


def split_url(url_link):
    url_parts = url_link.split("/")
    url = 'https://'+url_parts[2]
    digest = url_parts[4] if len(url_parts) > 4 else url_parts[3]
    return url, digest


def get_project_address(proxy):
    while True:
        try:
            session = setup_session(proxy)
            data = {
                "operationName": "SubscriberEdition",
                "variables": {
                    "address": web3.to_checksum_address(NFT_CONTRACT_ADDRESS),
                    "tokenId": 0
                },
                "query": "query SubscriberEdition($address: String, $tokenId: Int) {\n  subscriberEdition(address: $address, tokenId: $tokenId) {\n    _id\n    address\n    tokenId\n    type\n    title\n    description\n    media {\n      mimetype\n      url\n      __typename\n    }\n    price\n    tokenStandard\n    chainId\n    endsAt\n    collectorCount\n    publisher {\n      ...publisherDetails\n      __typename\n    }\n    __typename\n  }\n}\n\nfragment publisherDetails on PublisherType {\n  project {\n    ...projectDetails\n    __typename\n  }\n  member {\n    ...projectDetails\n    __typename\n  }\n  __typename\n}\n\nfragment projectDetails on ProjectType {\n  _id\n  address\n  avatarURL\n  description\n  displayName\n  domain\n  ens\n  gaTrackingID\n  ga4TrackingID\n  mailingListURL\n  headerImage {\n    ...mediaAsset\n    __typename\n  }\n  theme {\n    ...themeDetails\n    __typename\n  }\n  __typename\n}\n\nfragment mediaAsset on MediaAssetType {\n  id\n  cid\n  mimetype\n  sizes {\n    ...mediaAssetSizes\n    __typename\n  }\n  url\n  __typename\n}\n\nfragment mediaAssetSizes on MediaAssetSizesType {\n  og {\n    ...mediaAssetSize\n    __typename\n  }\n  lg {\n    ...mediaAssetSize\n    __typename\n  }\n  md {\n    ...mediaAssetSize\n    __typename\n  }\n  sm {\n    ...mediaAssetSize\n    __typename\n  }\n  __typename\n}\n\nfragment mediaAssetSize on MediaAssetSizeType {\n  src\n  height\n  width\n  __typename\n}\n\nfragment themeDetails on UserProfileThemeType {\n  accent\n  colorMode\n  __typename\n}\n"
            }
            resp = session.post(f'{url}/api/graphql', json=data)
            if resp.status_code != 200:
                logger.error(f"Error get_project_address request: {resp.text}")
                sleep(5)
                continue
            project_address = resp.json()['data']['subscriberEdition']['publisher']['project']['address']
            return project_address
        except Exception as error:
            logger.error(f"Unexcepted error get_project_address request: {error}")
            sleep(5)


def get_info_about_subscription(session, address, i):
    while True:
        try:
            data = {
                "operationName": "IsSubscribed",
                "variables": {
                    "projectAddress": project_address,
                    "walletAddress": address
                },
                "query": "query IsSubscribed($projectAddress: String!, $walletAddress: String) {\n  isSubscribed(projectAddress: $projectAddress, walletAddress: $walletAddress)\n}\n"
            }
            resp = session.post(f'{url}/api/graphql', json=data)
            if resp.status_code != 200:
                logger.error(f"{i}) Error get_info_about_subscription request: {address}")
                sleep(5)
                continue
            if resp.json()['data']['isSubscribed']:
                logger.info(f"{i}) Already subscribed")
                return True
            else:
                logger.info(f"{i}) Not subscribed. Trying to subscribe...")
                return False
        except Exception as error:
            logger.error(f"{i}) Unexcepted error get_info_about_subscription request: {error}")
            sleep(5)


def get_info_about_email_confirm(session, address, private_key, i):
    try:
        data = {
            "operationName": "SubscriptionEmail",
            "variables": {
            "walletAddress": address
            },
            "query": "query SubscriptionEmail($walletAddress: String!) {\n  subscriptionEmail(walletAddress: $walletAddress) {\n    ...emailVerificationDetails\n    __typename\n  }\n}\n\nfragment emailVerificationDetails on EmailVerificationType {\n  _id\n  maskedEmail\n  verificationStatus\n  __typename\n}\n"
        }
        resp = session.post(f'{url}/api/graphql', json=data)
        if resp.status_code != 200:
            logger.error(f"{i}) Error get_info_about_email_confirm request: {resp.status_code, resp.text}")
            return
        if resp.json()['data']['subscriptionEmail']['verificationStatus'] == 'EMAIL_NOT_SUBMITTED':
            logger.info(f"{i}) Email not linked")
            return 'NOT_SUBMITTED'
        elif resp.json()['data']['subscriptionEmail']['verificationStatus'] == 'EMAIL_NOT_VERIFIED':
            logger.info(f"{i}) Email not verified")
            return 'NOT_VERIFIED'
        elif resp.json()['data']['subscriptionEmail']['verificationStatus'] == 'EMAIL_VERIFIED':
            logger.info(f"{i}) Email already verified")
            rmail = resp.json()['data']['subscriptionEmail']['maskedEmail']
            if address not in registered_wallets:
                with open(file_registered, 'a') as file:
                    file.write(f"{address}:{private_key}:{rmail}:{None}\n")
            return 'VERIFIED'
        else:
            logger.info(f"{i}) Error get_info_about_email_confirm request: {resp.status_code, resp.text}")
            return    
    except Exception as error:
        logger.error(f"{i}) Unexcepted error get_info_about_email_confirm request: {error}")
        return


def get_code(mail):
    formatted_mail = mail.replace('=\n', '')
    index1 = formatted_mail.find('break-all">')
    index2 = formatted_mail.find('</span></a>')
    h_url = formatted_mail[index1+11:index2]
    code = h_url.split('/')[6]
    return(code)


def unlink_email(session, address, private_key, i):
    try:
        data = {
            "operationName": "SubscriptionSigningMessage",
            "variables": {
                "projectAddress": address,
                "walletAddress": address,
                "type": "UNLINK_EMAIL"
            },
            "query": "query SubscriptionSigningMessage($email: String, $projectAddress: String!, $walletAddress: String!, $type: SubscriptionSigningMessageEnumType) {\n  subscriptionSigningMessage(\n    email: $email\n    projectAddress: $projectAddress\n    walletAddress: $walletAddress\n    type: $type\n  )\n}\n"
        }
        resp = session.post(f'{url}/api/graphql', json=data)
        if resp.status_code != 200:
            logger.error(f"{i}) Error unlink_email request_1: {resp.status_code, resp.text}")
            return False
        if resp.json()['data']['subscriptionSigningMessage']:
            message = resp.json()['data']['subscriptionSigningMessage']
        else:
            logger.error(f"{i}) Error unlink_email request_1: clear respose {resp.text}")
            return False
    except Exception as error:
        logger.error(f"{i}) Unexcepted error unlink_email request_1: {error}")
        return False

    signature = web3.eth.account.sign_message(encode_defunct(text=message), private_key=private_key).signature.hex()
    sleep(1)

    try:
        data = {
            "operationName": "UnlinkEmail",
            "variables": {
                "signature": signature,
                "signedMessage": message,
                "walletAddress": address
            },
            "query": "mutation UnlinkEmail($walletAddress: String!, $signedMessage: String!, $signature: String!) {\n  unlinkEmail(\n    walletAddress: $walletAddress\n    signedMessage: $signedMessage\n    signature: $signature\n  ) {\n    ...emailVerificationDetails\n    __typename\n  }\n}\n\nfragment emailVerificationDetails on EmailVerificationType {\n  _id\n  maskedEmail\n  verificationStatus\n  __typename\n}\n"
        }
        resp = session.post(f'{url}/api/graphql', json=data)
        if resp.status_code != 200:
            logger.error(f"{i}) Error unlink_email request_2: {resp.status_code, resp.text}")
            return False
        if resp.json()['data']['unlinkEmail']['verificationStatus'] and resp.json()['data']['unlinkEmail']['verificationStatus'] == 'EMAIL_NOT_SUBMITTED':
            logger.info(f"{i}) Old email unlinked")
            return True
        else:
            logger.info(f"{i}) Error unlink_email: {resp.text}")
            return False
    except Exception as error:
        logger.error(f"{i}) Unexcepted error unlink_email request_2: {error}")
        return False


def link_email(session, address, private_key, i):
    email = available_emails.pop()
    email_imap = emailImap(email[0], email[1], IMAP_SERVER, IMAP_FOLDER)

    while True:
        try:
            mail_numbers_before = email_imap.get_number_of_mails()
            break
        except Exception:
            sleep(1)
        
    try:
        data = {
            "operationName": "SubscriptionSigningMessage",
            "variables": {
                "email": email[0],
                "projectAddress": address,
                "walletAddress": address,
                "type": "LINK_EMAIL"
            },
            "query": "query SubscriptionSigningMessage($email: String, $projectAddress: String!, $walletAddress: String!, $type: SubscriptionSigningMessageEnumType) {\n  subscriptionSigningMessage(\n    email: $email\n    projectAddress: $projectAddress\n    walletAddress: $walletAddress\n    type: $type\n  )\n}\n"
        }
        resp = session.post(f'{url}/api/graphql', json=data)
        if resp.status_code != 200:
            logger.error(f"{i}) Error link_email request_1: {resp.status_code, resp.text}")
            return False
        if resp.json()['data']['subscriptionSigningMessage']:
            message = resp.json()['data']['subscriptionSigningMessage']
        else:
            logger.error(f"{i}) Error link_email request_1: clear respose {resp.text}")
            return False
    except Exception as error:
        logger.error(f"{i}) Unexcepted error link_email request_1: {error}")
        return False

    signature = web3.eth.account.sign_message(encode_defunct(text=message), private_key=private_key).signature.hex()
    sleep(1)
    
    try:
        data = {
            "operationName": "LinkEmail",
            "variables": {
                "email": email[0],
                "signature": signature,
                "signedMessage": message,
                "walletAddress": address
            },
            "query": "mutation LinkEmail($email: String!, $walletAddress: String!, $signedMessage: String!, $signature: String!, $walletlessSubscriptionToken: String) {\n  linkEmail(\n    email: $email\n    walletAddress: $walletAddress\n    signedMessage: $signedMessage\n    signature: $signature\n    walletlessSubscriptionToken: $walletlessSubscriptionToken\n  ) {\n    ...emailVerificationDetails\n    __typename\n  }\n}\n\nfragment emailVerificationDetails on EmailVerificationType {\n  _id\n  maskedEmail\n  verificationStatus\n  __typename\n}\n"
        }
        resp = session.post(f'{url}/api/graphql', json=data)
        if resp.status_code != 200:
            logger.error(f"{i}) Error link_email request_2: {resp.status_code, resp.text}")
            return False
        if resp.json()['data']['linkEmail']['verificationStatus'] and resp.json()['data']['linkEmail']['verificationStatus'] == 'EMAIL_VERIFIED':
            logger.info(f"{i}) Email already linked")
            return True
        elif resp.json()['data']['linkEmail']['verificationStatus'] and resp.json()['data']['linkEmail']['verificationStatus'] == 'EMAIL_NOT_VERIFIED':
            logger.info(f"{i}) Trying to verify email {email[0]}...")
        else:
            logger.info(f"{i}) Error link email: {resp.text}")
            return False
    except Exception as error:
        logger.error(f"{i}) Unexcepted error link_email request_2: {error}")
        return False

    stime = time()
    while True:
        try:
            token = get_code(email_imap.get_new_mail(mail_numbers_before, stime))
            logger.info(f"{i}) Email verification token received")
            break
        except TimeoutError:
            logger.error(f"{i}) Timeout 100s error 'get email'")
            with open(file_dismissed_emails, 'a') as file:
                file.write(f'{email[0]}:{email[1]}\n')
            return False
        except Exception as error:
            sleep(1)

    try:
        data = {
            "operationName": "VerifyEmailToken",
            "variables": {
                "token": token,
                "walletAddress": address
            },
            "query": "mutation VerifyEmailToken($token: String!, $walletAddress: String!) {\n  verifyEmailToken(token: $token, walletAddress: $walletAddress) {\n    ...emailVerificationDetails\n    __typename\n  }\n}\n\nfragment emailVerificationDetails on EmailVerificationType {\n  _id\n  maskedEmail\n  verificationStatus\n  __typename\n}\n"
        }
        resp = session.post(f'{url}/api/graphql', json=data)
        if resp.status_code != 200:
            logger.error(f"{i}) Error link_email request_3: {resp.status_code, resp.text}")
            return False
        if resp.json()['data']['verifyEmailToken']['verificationStatus'] and resp.json()['data']['verifyEmailToken']['verificationStatus'] == 'EMAIL_VERIFIED':
            logger.success(f"{i}) Successfully linked email")
            txt = f'{address}:{private_key}:{email[0]}:{email[1]}'
            if address in registered_wallets:
                with open(file_registered, 'r') as file:
                    fdata = [row.strip() for row in file]
                old = f"{fdata[registered_wallets.index(address)].split(':')[2]}:{fdata[registered_wallets.index(address)].split(':')[3]}"
                fdata[registered_wallets.index(address)] = txt
                with open(file_registered, 'w') as file:
                    for line in fdata:
                        file.write(f"{line}\n")
                with open(file_dismissed_emails, 'a') as file:
                    file.write(f"{old}\n")
            else:
                with open (file_registered, 'a') as file:
                    file.write(f"{txt}\n")
            return True
        else:
            logger.error(f"{i}) Error link_email: {resp.json()['data']['verifyEmailToken']['verificationStatus']}")
            return False
    except Exception as error:
        logger.error(f"{i}) Unexcepted error link_email request_3: {error}")
        return False


def subscribe(session, i):
    while True:
        try:
            data = {
                "operationName": "Subscribe",
                "variables": {
                    "projectAddress": project_address,
                    "source": "SubscriberEdition"
                },
                "query": "mutation Subscribe($projectAddress: String!, $source: String) {\n  subscribe(projectAddress: $projectAddress, source: $source) {\n    ...emailVerificationDetails\n    __typename\n  }\n}\n\nfragment emailVerificationDetails on EmailVerificationType {\n  _id\n  maskedEmail\n  verificationStatus\n  __typename\n}\n"
            }
            resp = session.post(f'{url}/api/graphql', json=data)
            if resp.status_code != 200:
                logger.error(f"{i}) Error subscribe request: {resp.status_code, resp.text}")
                sleep(5)
            if resp.json()['data']['subscribe']['_id']:
                logger.success(f"{i}) Successfully subscribed")
                break
            else:
                logger.error(f"{i}) Error subscribe: {resp.text}")
                sleep(5)
        except Exception as error:
            logger.error(f"{i}) Unexcepted error subscribe request: {error} {resp.text}")
            sleep(5)


def sign_in_session(session, address, private_key, i):
    try:
        curve = ec.SECP256R1()
        backend = default_backend()
        public_key = ec.generate_private_key(curve, backend).public_key()
        x = public_key.public_numbers().x
        y = public_key.public_numbers().y
        x_b64 = base64.urlsafe_b64encode(x.to_bytes(32, 'big')).rstrip(b'=').decode()
        y_b64 = base64.urlsafe_b64encode(y.to_bytes(32, 'big')).rstrip(b'=').decode()
        now = datetime.utcnow()
        iso_time = now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        nonce = ''.join(secrets.choice('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') for i in range(17))
        logger.info(f'{i}) Generated login public key point and nonce')
        message = f"{url.split('://')[1]} wants you to sign in with your Ethereum account:\n{address}\n\nSign in with public key: ('crv':'P-256','ext':true,'key_ops':['verify'],'kty':'EC','x':'{x_b64}','y':'{y_b64}')\n\nURI: {url}\nVersion: 1\nChain ID: 1\nNonce: {nonce}\nIssued At: {iso_time}"
        signature = web3.eth.account.sign_message(encode_defunct(text=message), private_key=private_key).signature.hex()
        public_key_dict = {
            "crv": "P-256",
            "ext": True,
            "key_ops": ["verify"],
            "kty": "EC",
            "x": x_b64,
            "y": x_b64
        }
        data = {
            "operationName": "signIn",
            "variables": {
                "address": address,
                "publicKey": json.dumps(public_key_dict),
                "signature": signature,
                "message": message
            },
            "query": "mutation signIn($address: String!, $publicKey: String!, $signature: String!, $message: String!) {\n  signIn(\n    address: $address\n    publicKey: $publicKey\n    signature: $signature\n    message: $message\n  ) {\n    _id\n    __typename\n  }\n}\n"
        }
        resp = session.post(f'{url}/api/graphql', json=data)
        if resp.status_code != 200:
            logger.error(f"{i}) Error sign_in_session request: {resp.status_code, resp.text}")
            return False
        if resp.json()['data']['signIn']:
            logger.success(f"{i}) Successfully signed in!")
            return True
        else:
            logger.error(f"{i}) Error sign_in_session: {resp.text}")
            return False
    except Exception as error:
        logger.error(f"{i}) Unexcepted error sign_in_session request: {error}")
        return False


def get_mint_nft_payload(session, address, i):
    while True:
        try:
            data = {
                "operationName": "SubscriberEditionSignature",
                "variables": {
                    "projectAddress": project_address,
                    "walletAddress": address,
                    "editionAddress": web3.to_checksum_address(NFT_CONTRACT_ADDRESS),
                    "tokenId": int(0),
                    "dryRun": False,
                },
                "query": "query SubscriberEditionSignature($projectAddress: String, $walletAddress: String, $editionAddress: String, $tokenId: Int, $dryRun: Boolean) {\n  subscriberEditionSignature(\n    projectAddress: $projectAddress\n    walletAddress: $walletAddress\n    editionAddress: $editionAddress\n    tokenId: $tokenId\n    dryRun: $dryRun\n  ) {\n    signedPayload\n    result\n    __typename\n  }\n}\n"
            }
            resp = session.post(f'{url}/api/graphql', json=data)
            if resp.status_code != 200:
                logger.error(f"{i}) Error get_mint_nft_payloadd request: {resp.status_code, resp.text}")
                sleep(5)
            if resp.json()['data']['subscriberEditionSignature']['result'] == 'Success':
                str_data = resp.json()['data']['subscriberEditionSignature']['signedPayload']
                new_data = json.loads(str_data)
                signature = new_data['signature']
                uid = new_data['payload']['uid']
                tvalue = float(new_data['payload']['price'])
                hex_value = new_data['payload']['mintEndTime']['hex']
                logger.success(f"{i}) Mint payload received!")
                mint_payload = (
                        address,
                        '0x0000000000000000000000000000000000000000',
                        0,
                        '0x0000000000000000000000000000000000000000',
                        0,
                        '',
                        1,
                        int(tvalue*10**18),
                        '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE',
                        0,
                        int(hex_value, 16),
                        uid
                    )
                return mint_payload, signature
            elif resp.json()['data']['subscriberEditionSignature']['result'] == 'Already minted':
                logger.info(f"{i}) Account already minted")
                return None, None
            else:
                logger.error(f"{i}) Error get_mint_nft_payload request: {resp.text}")
                sleep(5)
        except Exception as error:
            logger.error(f"{i}) Unexcepted error get_mint_nft_payload request: {error}")
            sleep(5)


def mint_nft(address, private_key, mint_payload, signature, i):
    try:
        contract = web3.eth.contract(address=web3.to_checksum_address(NFT_CONTRACT_ADDRESS), abi=NFT_ABI)
        transaction = contract.functions.mintWithSignature(mint_payload, signature).build_transaction({
                'nonce': int(web3.eth.get_transaction_count(address)),
                'gasPrice': web3.eth.gas_price,
                'chainId': CHAIN_ID,
                'from': address,
                'gas': 180000,
                'value': int(VALUE * 10**18),
        })
        #transaction['gas'] = int(web3.eth.estimate_gas(transaction) * 1.1)
        signed_txn = web3.eth.account.sign_transaction(transaction, private_key)
        tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
        logger.info(f"{i}) Mint tx hash: {tx_hash.hex()}")
        data = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=1000, poll_latency=0.3)
        status = True if data['status'] == 1 else False
        return (tx_hash.hex(), status)
    except Exception as error:
        if 'already minted' in str(error):
            logger.info(f"{i}) Account already minted")
        if 'insufficient funds' in str(error):
            logger.error(f"{i}) Not enough funds to mint")
        else:
            logger.error(f"{i}) Unexcepted mint_entry error: {error}")
        return (None, False)


def get_mint_first_entry_payload(session, address, i):
    while True:
        try:
            data = {
                "operationName": "WritingNFT",
                "variables": {
                "digest": digest
                },
                "query": "query WritingNFT($digest: String!) {\n  entry(digest: $digest) {\n    _id\n    digest\n    arweaveTransactionRequest {\n      transactionId\n      __typename\n    }\n    writingNFT {\n      ...writingNFTDetails\n      media {\n        ...mediaAsset\n        __typename\n      }\n      network {\n        ...networkDetails\n        __typename\n      }\n      intents {\n        ...writingNFTPurchaseDetails\n        __typename\n      }\n      purchases {\n        ...writingNFTPurchaseDetails\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n\nfragment writingNFTDetails on WritingNFTType {\n  _id\n  contractURI\n  contentURI\n  deploymentSignature\n  deploymentSignatureType\n  description\n  digest\n  fee\n  fundingRecipient\n  imageURI\n  canMint\n  media {\n    id\n    cid\n    __typename\n  }\n  nonce\n  optimisticNumSold\n  owner\n  price\n  proxyAddress\n  publisher {\n    project {\n      ...writingNFTProjectDetails\n      __typename\n    }\n    __typename\n  }\n  quantity\n  renderer\n  signature\n  symbol\n  timestamp\n  title\n  version\n  __typename\n}\n\nfragment writingNFTProjectDetails on ProjectType {\n  _id\n  address\n  avatarURL\n  displayName\n  domain\n  ens\n  __typename\n}\n\nfragment mediaAsset on MediaAssetType {\n  id\n  cid\n  mimetype\n  sizes {\n    ...mediaAssetSizes\n    __typename\n  }\n  url\n  __typename\n}\n\nfragment mediaAssetSizes on MediaAssetSizesType {\n  og {\n    ...mediaAssetSize\n    __typename\n  }\n  lg {\n    ...mediaAssetSize\n    __typename\n  }\n  md {\n    ...mediaAssetSize\n    __typename\n  }\n  sm {\n    ...mediaAssetSize\n    __typename\n  }\n  __typename\n}\n\nfragment mediaAssetSize on MediaAssetSizeType {\n  src\n  height\n  width\n  __typename\n}\n\nfragment networkDetails on NetworkType {\n  _id\n  chainId\n  name\n  explorerURL\n  currency {\n    _id\n    name\n    symbol\n    decimals\n    __typename\n  }\n  __typename\n}\n\nfragment writingNFTPurchaseDetails on WritingNFTPurchaseType {\n  numSold\n  __typename\n}\n"
            }
            resp = session.post(f'{url}/api/graphql', json=data)
            if resp.status_code != 200:
                logger.error(f"{i}) Error get_mint_first_entry_payload request: {resp.status_code, resp.text}")
                sleep(5)
            info = resp.json()['data']['entry']['writingNFT']
            if info:
                owner = info['owner']
                sign = info['deploymentSignature']
                v = int(sign[-2:], 16)
                r = '0x'+sign[2:66]
                s = '0x'+sign[66:130]
                edition = {
                        'name': info['title'].replace('\n', ''),
                        'symbol': info['symbol'],
                        'description': info['description'].replace('\n', ''),
                        'imageURI': info['imageURI'],
                        'contentURI': info['contentURI'],
                        'price': int(info['price']*10**18),
                        'limit': info['quantity'],
                        'fundingRecipient': info['owner'],
                        'renderer': info['renderer'],
                        'nonce': info['nonce'],
                        'fee': info['fee']
                }
                logger.success(f"{i}) Mint payload received!")
                return (web3.to_checksum_address(owner), edition, v, r, s, address, '')
            else:
                logger.error(f"{i}) Error get_mint_first_entry_payload request: {resp.text}")
                sleep(5)
        except Exception as error:
            logger.error(f"{i}) Unexcepted error get_mint_first_entry_payload request: {error}")
            sleep(5)


def mint_fisrt_entry(address, private_key, mint_payload, i):
    try:
        contract = web3.eth.contract(address=web3.to_checksum_address(NFT_CONTRACT_ADDRESS), abi=FIRST_ENTRY_ABI)
        transaction = contract.functions.createWithSignature(*mint_payload).build_transaction({
                'nonce': web3.eth.get_transaction_count(address),
                'gasPrice': web3.eth.gas_price,
                'chainId': CHAIN_ID,
                'from': address,
                'gas': 180000,
        })
        #transaction['gas'] = int(web3.eth.estimate_gas(transaction) * 1.1)
        signed_txn = web3.eth.account.sign_transaction(transaction, private_key)
        tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
        logger.info(f"{i}) Mint tx hash: {tx_hash.hex()}")
        data = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=1000, poll_latency=0.3)
        status = True if data['status'] == 1 else False
        return (tx_hash.hex(), status)
    except Exception as error:
        logger.error(f"{i}) Unexcepted mint_fisrt_entry error: {error}")


def mint_entry(address, private_key, i):
    try:
        contract = web3.eth.contract(address=web3.to_checksum_address(NFT_CONTRACT_ADDRESS), abi=ENTRY_ABI)
        transaction = contract.functions.purchase(address, '').build_transaction({
                'nonce': web3.eth.get_transaction_count(address),
                'gasPrice': web3.eth.gas_price,
                'chainId': CHAIN_ID,
                'from': address,
                'value': int(VALUE * 10**18),
                'gas': 180000,
        })
        #transaction['gas'] = int(web3.eth.estimate_gas(transaction) * 1.1)
        signed_txn = web3.eth.account.sign_transaction(transaction, private_key)
        tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
        logger.info(f"{i}) Mint tx hash: {tx_hash.hex()}")
        data = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=120, poll_latency=0.15)
        status = True if data['status'] == 1 else False
        return (tx_hash.hex(), status)
    except Exception as error:
        if 'already minted' in str(error):
            logger.info(f"{i}) Account already minted")
        if 'insufficient funds' in str(error):
            logger.error(f"{i}) Not enough funds to mint")
        else:
            logger.error(f"{i}) Unexcepted mint_entry error: {error}")
        return (None, False)


def main(wallet, i):
    try:
        address = web3.to_checksum_address(wallet[0])
        private_key = wallet[1]
        proxy = proxies.pop()
        session = setup_session(proxy)

        logger.info(f'{i}) Account work: {address}  (proxy: {proxy.split("@")[1]})')

        if not sign_in_session(session, address, private_key, i):
            return
        status = get_info_about_email_confirm(session, address, private_key, i)  
        if status == 'NOT_SUBMITTED':
            if not link_email(session, address, private_key, i):
                return
        elif status == 'NOT_VERIFIED':
            if not unlink_email(session, address, private_key, i):
                return         
            if not link_email(session, address, private_key, i):
                return

        if not get_info_about_subscription(session, address, i):
            subscribe(session, i)

        if MINT_TYPE == 'NFT':
            mint_payload, signature = get_mint_nft_payload(session, address, i)
            if not mint_payload:
                with open(CLAIMED_FILE, 'a') as file:
                    file.write(f'{address}:{private_key}:{NFT_CONTRACT_ADDRESS}\n')
                return
            tx_hash, status = mint_nft(address, private_key, mint_payload, signature, i)
        elif MINT_TYPE == 'ENTRY':
            if FIRST_ENTRY_STATUS == 'True':
                mint_payload = get_mint_first_entry_payload(session, address, i)
                tx_hash, status = mint_fisrt_entry(address, private_key, mint_payload, i)
            elif FIRST_ENTRY_STATUS == 'False':
                tx_hash, status = mint_entry(address, private_key, i)   
            else:
                logger.error(f"{i}) INVALID FIRST_ENTRY_STATUS")
                exit()
        else:
            logger.error(f"{i}) INVALID MINT TYPE")
            exit()

        if status:
            logger.success(f"{i}) MINT SUCCESS!!!!!: (tx hash: {tx_hash})")
            with open(CLAIMED_FILE, 'a') as file:
                file.write(f'{address}:{private_key}:{NFT_CONTRACT_ADDRESS}\n')
        else:
            logger.error(f"{i}) MINT ERROR: (tx hash: {tx_hash})")
    except Exception as error:
        logger.error(f"{i}) Main error: {error}")
        return


if (__name__ == '__main__'):
    web3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER))
    url, digest = split_url(URL_LINK)

    with open('jsons/NFT_ABI.json', 'r') as file:
        NFT_ABI = json.load(file)
    with open('jsons/FIRST_ENTRY_ABI.json', 'r') as file:
        FIRST_ENTRY_ABI = json.load(file)
    with open('jsons/ENTRY_ABI.json', 'r') as file:
        ENTRY_ABI = json.load(file)

    if not os.path.isfile(CLAIMED_FILE):
        open(CLAIMED_FILE, 'w').close()
    if not os.path.isfile(file_registered):
        open(file_registered, 'w').close()
    if not os.path.isfile(file_dismissed_emails):
        open(file_dismissed_emails, 'w').close()

    with open(file_wallets, 'r') as file:
        all_wallets = [[row.strip().split(':')[0],row.strip().split(':')[1]] for row in file]
    with open(file_mails, 'r') as file:
        all_emails = [[row.strip().split(':')[0],row.strip().split(':')[1]] for row in file]
    with open(file_proxies, 'r') as file:
        proxies = [row.strip() for row in file]
    with open(file_registered, 'r') as file:
        registered_wallets = [row.strip().split(':')[0] for row in file]
    with open(file_registered, 'r') as file:
        registered_emails = [[row.strip().split(':')[2],row.strip().split(':')[3]] for row in file]
    with open(file_dismissed_emails, 'r') as file:
        dismissed_emails = [row.strip().split(':') for row in file]
    with open(CLAIMED_FILE, 'r') as file:
        claimed_wallets = [[row.strip().split(':')[0],row.strip().split(':')[1]] for row in file] 

    available_emails = [x for x in all_emails if x not in registered_emails and x not in dismissed_emails]
    available_emails.reverse()
    wallets = [x for x in all_wallets if x not in claimed_wallets]
    while len(proxies) <= len(wallets):
        proxies.extend(proxies)

    project_address = web3.to_checksum_address(get_project_address(proxies[0]))

    with concurrent.futures.ThreadPoolExecutor(THREADS) as executor:
        for i, wallet in enumerate(wallets):
            executor.submit(
                main, wallet, i
            )
