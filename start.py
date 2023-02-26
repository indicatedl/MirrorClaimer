import requests
import json
import os
import concurrent.futures
from time import time, sleep
from sys import stderr, exit

import ua_generator
from web3 import Web3
from loguru import logger
from eth_account.messages import encode_defunct
from dotenv import dotenv_values

from modules.emailimap import emailImap

# FILE SETTINGS
file_wallets = 'files/wallets.txt'
file_proxies = 'files/proxies.txt'
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
            'pragma': f'{url}/',
            'referer': 'https://optimism.mirror.xyz/',
            'sec-ch-ua': f'"{ua.ch.brands[2:]}',
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
    if len(url_parts) > 4:
        digest = url_parts[4]
    else:
        digest = url_parts[3]
    return url, digest


def get_project_address(proxy):
    while True:
        try:
            session = setup_session(proxy)
            data = {
                "operationName": "WritingNFT",
                "variables": {
                "digest": digest
                },
                "query": "query WritingNFT($digest: String!) {\n  entry(digest: $digest) {\n    _id\n    digest\n    arweaveTransactionRequest {\n      transactionId\n      __typename\n    }\n    writingNFT {\n      ...writingNFTDetails\n      media {\n        ...mediaAsset\n        __typename\n      }\n      network {\n        ...networkDetails\n        __typename\n      }\n      intents {\n        ...writingNFTPurchaseDetails\n        __typename\n      }\n      purchases {\n        ...writingNFTPurchaseDetails\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n\nfragment writingNFTDetails on WritingNFTType {\n  _id\n  contractURI\n  contentURI\n  deploymentSignature\n  deploymentSignatureType\n  description\n  digest\n  fee\n  fundingRecipient\n  imageURI\n  canMint\n  media {\n    id\n    cid\n    __typename\n  }\n  nonce\n  optimisticNumSold\n  owner\n  price\n  proxyAddress\n  publisher {\n    project {\n      ...writingNFTProjectDetails\n      __typename\n    }\n    __typename\n  }\n  quantity\n  renderer\n  signature\n  symbol\n  timestamp\n  title\n  version\n  __typename\n}\n\nfragment writingNFTProjectDetails on ProjectType {\n  _id\n  address\n  avatarURL\n  displayName\n  domain\n  ens\n  __typename\n}\n\nfragment mediaAsset on MediaAssetType {\n  id\n  cid\n  mimetype\n  sizes {\n    ...mediaAssetSizes\n    __typename\n  }\n  url\n  __typename\n}\n\nfragment mediaAssetSizes on MediaAssetSizesType {\n  og {\n    ...mediaAssetSize\n    __typename\n  }\n  lg {\n    ...mediaAssetSize\n    __typename\n  }\n  md {\n    ...mediaAssetSize\n    __typename\n  }\n  sm {\n    ...mediaAssetSize\n    __typename\n  }\n  __typename\n}\n\nfragment mediaAssetSize on MediaAssetSizeType {\n  src\n  height\n  width\n  __typename\n}\n\nfragment networkDetails on NetworkType {\n  _id\n  chainId\n  name\n  explorerURL\n  currency {\n    _id\n    name\n    symbol\n    decimals\n    __typename\n  }\n  __typename\n}\n\nfragment writingNFTPurchaseDetails on WritingNFTPurchaseType {\n  numSold\n  __typename\n}\n"
            }
            resp = session.post(f'https://mirror-api.com/graphql', json=data)
            if resp.status_code != 200:
                logger.error(f"Error get_project_address request: {resp.text}")
                sleep(5)
                continue
            project_address = resp.json()['data']['entry']['writingNFT']['publisher']['project']['address']
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
            resp = session.post(f'https://mirror-api.com/graphql', json=data)
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


def get_info_about_email_confirm(session, address, email, i):
    while True:
        try:
            data = {
                "operationName": "SubscriptionEmail",
                "variables": {
                "walletAddress": address
                },
                "query": "query SubscriptionEmail($walletAddress: String!) {\n  subscriptionEmail(walletAddress: $walletAddress) {\n    ...emailVerificationDetails\n    __typename\n  }\n}\n\nfragment emailVerificationDetails on EmailVerificationType {\n  _id\n  maskedEmail\n  verificationStatus\n  __typename\n}\n"
            }
            resp = session.post(f'https://mirror-api.com/graphql', json=data)
            if resp.status_code != 200:
                logger.error(f"{i}) Error get_info_about_email_confirm request: {resp.status_code, resp.text}")
                sleep(5)
                continue
            if resp.json()['data']['subscriptionEmail']['verificationStatus'] == 'EMAIL_NOT_SUBMITTED':
                logger.info(f"{i}) Email not linked. Trying to link... ")
                return False
            elif resp.json()['data']['subscriptionEmail']['verificationStatus'] == 'EMAIL_NOT_VERIFIED':
                logger.info(f"{i}) Email not verified. Trying to verify... ")
                return False
            elif resp.json()['data']['subscriptionEmail']['verificationStatus'] == 'EMAIL_VERIFIED':
                logger.info(f"{i}) Email already linked")
                return True
            else:
                logger.info(f"{i}) Error get_info_about_email_confirm request: {resp.status_code, resp.text}")
                sleep(5)     
        except Exception as error:
            logger.error(f"{i}) Unexcepted error get_info_about_email_confirm request: {error}")
            sleep(5)


def get_code(mail):
    formatted_mail = mail.replace('=\n', '')
    index1 = formatted_mail.find('break-all">')
    index2 = formatted_mail.find('</span></a>')
    h_url = formatted_mail[index1+11:index2]
    code = h_url.split('/')[6]
    return(code)


def link_email(session, address, private_key, email, i):
    email_imap = emailImap(email[0], email[1], IMAP_SERVER, IMAP_FOLDER)

    while True:
        try:
            mail_numbers_before = email_imap.get_number_of_mails()
            break
        except:
            pass
        
    while True:
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
            resp = session.post(f'https://mirror-api.com/graphql', json=data)
            if resp.status_code != 200:
                logger.error(f"{i}) Error link_email request_1: {resp.status_code, resp.text}")
                sleep(5)
                continue
            if resp.json()['data']['subscriptionSigningMessage']:
                message = resp.json()['data']['subscriptionSigningMessage']
                break
            else:
                logger.error(f"{i}) Error link_email request_1: clear respose {resp.text}")
                sleep(5)
        except Exception as error:
            logger.error(f"{i}) Unexcepted error link_email request_1: {error}")
            sleep(5)

    signature = web3.eth.account.sign_message(encode_defunct(text=message), private_key=private_key).signature.hex()
    sleep(1)
    
    while True:
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
            resp = session.post(f'https://mirror-api.com/graphql', json=data)
            if resp.status_code != 200:
                logger.error(f"{i}) Error link_email request_2: {resp.status_code, resp.text}")
                sleep(5)
                continue
            if resp.json()['data']['linkEmail']['verificationStatus'] and resp.json()['data']['linkEmail']['verificationStatus'] == 'EMAIL_VERIFIED':
                logger.info(f"{i}) Email already linked")
                return
            elif resp.json()['data']['linkEmail']['verificationStatus'] and resp.json()['data']['linkEmail']['verificationStatus'] == 'EMAIL_NOT_VERIFIED':
                logger.info(f"{i}) Trying to verify email...")
                break
            else:
                logger.info(f"{i}) Error link email: {resp.text}")
        except Exception as error:
            logger.error(f"{i}) Unexcepted error link_email request_2: {error}")
            sleep(5)

    while True:
        try:
            token = get_code(email_imap.get_new_mail(mail_numbers_before))
            logger.info(f"{i}) Get token: {token}")
            break
        except Exception as error:
            sleep(1)

    while True:
        try:
            data = {
                "operationName": "VerifyEmailToken",
                "variables": {
                    "token": token,
                    "walletAddress": address
                },
                "query": "mutation VerifyEmailToken($token: String!, $walletAddress: String!) {\n  verifyEmailToken(token: $token, walletAddress: $walletAddress) {\n    ...emailVerificationDetails\n    __typename\n  }\n}\n\nfragment emailVerificationDetails on EmailVerificationType {\n  _id\n  maskedEmail\n  verificationStatus\n  __typename\n}\n"
            }
            resp = session.post(f'https://mirror-api.com/graphql', json=data)
            if resp.status_code != 200:
                logger.error(f"{i}) Error link_email request_3: {resp.status_code, resp.text}")
                sleep(5)
                continue
            if resp.json()['data']['verifyEmailToken']['verificationStatus'] and resp.json()['data']['verifyEmailToken']['verificationStatus'] == 'EMAIL_VERIFIED':
                logger.success(f"{i}) Successfully linked email")
                return True
            else:
                logger.error(f"{i}) Error link_email: {resp.status_code, resp.text}")
                sleep(5)
        except Exception as error:
            logger.error(f"{i}) Unexcepted error link_email request_3: {error}")
            sleep(5)


def subscribe(session, address, private_key, i):
    while True:
        try:
            data = {
                "operationName": "SubscriptionSigningMessage",
                "variables": {
                    "projectAddress": project_address,
                    "walletAddress": address,
                    "type": "SUBSCRIBE"
                },
                "query": "query SubscriptionSigningMessage($email: String, $projectAddress: String!, $walletAddress: String!, $type: SubscriptionSigningMessageEnumType) {\n  subscriptionSigningMessage(\n    email: $email\n    projectAddress: $projectAddress\n    walletAddress: $walletAddress\n    type: $type\n  )\n}\n"
            }
            resp = session.post(f'https://mirror-api.com/graphql', json=data)
            if resp.status_code != 200:
                logger.error(f"{i}) Error subscribe request_1: {resp.status_code, resp.text}")
                sleep(5)
                continue
            if resp.json()['data']['subscriptionSigningMessage']:
                message = resp.json()['data']['subscriptionSigningMessage']
                break
            else:
                logger.error(f"{i}) Error subscribe request_1: clear respose {resp.text}")
                sleep(5)
                continue
        except Exception as error:
            logger.error(f"{i}) Unexcepted error subscribe request_1: {error}")
            sleep(5)

    signature = web3.eth.account.sign_message(encode_defunct(text=message), private_key=private_key).signature.hex()
    sleep(1)

    while True:
        try:
            data = {
                "operationName": "Subscribe",
                "variables": {
                    "projectAddress": project_address,
                    "signature": signature,
                    "signedMessage": message,
                    "walletAddress": address,
                    "source": "SubscriberEdition"
                },
                "query": "mutation Subscribe($projectAddress: String!, $walletAddress: String!, $signedMessage: String!, $signature: String!, $source: String) {\n  subscribe(\n    projectAddress: $projectAddress\n    walletAddress: $walletAddress\n    signedMessage: $signedMessage\n    signature: $signature\n    source: $source\n  ) {\n    ...emailVerificationDetails\n    __typename\n  }\n}\n\nfragment emailVerificationDetails on EmailVerificationType {\n  _id\n  maskedEmail\n  verificationStatus\n  __typename\n}\n"
            }
            resp = session.post(f'https://mirror-api.com/graphql', json=data)
            if resp.status_code != 200:
                logger.error(f"{i}) Error subscribe request_2: {resp.status_code, resp.text}")
                sleep(5)
            logger.success(f"{i}) Successfully subscribed!")
            break
        except Exception as error:
            logger.error(f"{i}) Unexcepted error subscribe request_2: {error}")
            sleep(5)


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
            resp = session.post(f'https://mirror-api.com/graphql', json=data)
            if resp.status_code != 200:
                logger.error(f"{i}) Error get_mint_nft_payloadd request: {resp.status_code, resp.text}")
                sleep(5)
            if resp.json()['data']['subscriberEditionSignature']['result'] == 'Success':
                str_data = signature = resp.json()['data']['subscriberEditionSignature']['signedPayload']
                new_data = json.loads(str_data)
                signature = new_data['signature']
                uid = new_data['payload']['uid']
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
                        0,
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
                'gasPrice': int(web3.eth.gas_price * 1.1),
                'chainId': CHAIN_ID,
                'from': address,
                'gas': 180000,
                'value': int(VALUE * 10**18),
        })
        #transaction['gas'] = int(web3.eth.estimate_gas(transaction) * 1.1)
        signed_txn = web3.eth.account.sign_transaction(transaction, private_key)
        tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
        logger.info(f"{i}) Mint tx hash: {tx_hash.hex()}")
        data = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=120, poll_latency=0.15)
        status = True if data['status'] == 1 else False
        return (tx_hash.hex(), status)
    except Exception as error:
        logger.error(f"{i}) Unexcepted mint_free_nft error: {error}")


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
            resp = session.post(f'https://mirror-api.com/graphql', json=data)
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
                'nonce': int(web3.eth.get_transaction_count(address)),
                'gasPrice': int(web3.eth.gas_price * 1.1),
                'chainId': CHAIN_ID,
                'from': address,
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
        logger.error(f"{i}) Unexcepted mint_fisrt_entry error: {error}")


def mint_entry(address, private_key, i):
    try:
        contract = web3.eth.contract(address=web3.to_checksum_address(NFT_CONTRACT_ADDRESS), abi=ENTRY_ABI)
        transaction = contract.functions.purchase(address, '').build_transaction({
                'nonce': int(web3.eth.get_transaction_count(address)),
                'gasPrice': int(web3.eth.gas_price * 1.1),
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
        logger.error(f"{i}) Unexcepted mint_entry error: {error}")


def main(wallet, email, proxy, i):
    address = web3.to_checksum_address(wallet[0])
    private_key = wallet[1]
    session = setup_session(proxy)

    logger.info(f'{i}) Account work: {address}')

    if not get_info_about_email_confirm(session, address, email[0], i):
        link_email(session, address, private_key, email, i)
    if not get_info_about_subscription(session, address, i):
        subscribe(session, address, private_key, i)


    if MINT_TYPE == 'NFT':
        mint_payload, signature = get_mint_nft_payload(session, address, i)
        if not mint_payload:
            with open(CLAIMED_FILE, 'a') as file:
                pass
                file.write(f'{address}:{private_key}:{email[0]}:{email[1]}:{NFT_CONTRACT_ADDRESS}')
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
        logger.success(f"{i}) MINT SUCCESS!!!!!!!: (tx hash: {tx_hash})")
        with open(CLAIMED_FILE, 'a') as file:
            pass
            file.write(f'{address}:{private_key}:{email[0]}:{email[1]}:{NFT_CONTRACT_ADDRESS}')
    else:
        logger.error(f"{i}) MINT ERROR: (tx hash: {tx_hash})")


if (__name__ == '__main__'):
    web3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER))
    url, digest = split_url(URL_LINK)

    with open('jsons/NFT_ABI.json', 'r') as file:
        NFT_ABI = json.load(file)
    with open('jsons/FIRST_ENTRY_ABI.json', 'r') as file:
        FIRST_ENTRY_ABI = json.load(file)
    with open('jsons/ENTRY_ABI.json', 'r') as file:
        ENTRY_ABI = json.load(file)
    with open(file_wallets, 'r') as file:
        all_wallets = [[row.strip().split(':')[0],row.strip().split(':')[1]] for row in file]
    with open(file_proxies, 'r') as file:
        proxies = [row.strip() for row in file]
    with open(file_mails, 'r') as file:
        all_emails = [[row.strip().split(':')[0],row.strip().split(':')[1]] for row in file]
    if not os.path.isfile(CLAIMED_FILE):
        open(CLAIMED_FILE, 'w').close()

    with open(CLAIMED_FILE, 'r') as file:
        registered_wallets = [[row.strip().split(':')[0],row.strip().split(':')[1]] for row in file] 
    with open(CLAIMED_FILE, 'r') as file:
        registered_mails = [[row.strip().split(':')[2],row.strip().split(':')[3]] for row in file]

    emails = [x for x in all_emails if (x not in registered_mails)]
    wallets = [x for x in all_wallets if (x not in registered_wallets)]
    while len(proxies) < len(wallets):
        proxies.append(*proxies)

    project_address = web3.to_checksum_address(get_project_address(proxies[0]))

    with concurrent.futures.ThreadPoolExecutor(5) as executor:
        futures = []
        for i, wallet, email, proxy in zip(range(1, len(wallets)+1), wallets, emails, proxies):
            futures.append(
                executor.submit(
                    main, wallet, email, proxy, i
                )
            )
