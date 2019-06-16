# coding:utf-8
# 多个未授权检测脚本
# usage: python3 Check_Unauth.py 127.0.0.1
# 1.mongodb默认端口和27017
# 2.zookeeper默认端口2181
# 3.Redis默认端口6379
# 4.elasticsearch未授权检测脚本默认端口9200
# 5.ftp、Memcached

import sys
import click
from pymongo import MongoClient

from redis import StrictRedis
from kazoo.client import KazooClient

import ftplib

from elasticsearch import Elasticsearch
import requests
import json

import socket
import re


def check_mongodb(ip):
	try:
		conn = MongoClient(ip, 28017, socketTimeoutMS=4000)  # 连接MongoDB,延时5秒
		dbs = conn.database_names()
		click.secho('[+] 存在mongodb未授权:', fg='red')
		# print('\033[31m[ok] -> {}:{}  mongodb : {}'.format(ip, 28017, dbs))
		conn.close()
	except Exception as e:
		pass

def check_mongodb1(ip):
	try:
		conn = MongoClient(ip, 27017, socketTimeoutMS=4000)  # 连接MongoDB,延时5秒
		dbs = conn.database_names()
		click.secho('[+] 存在mongodb未授权:', fg='red')
		conn.close()
	except Exception as e:
		print('[-] -> 不存在mongodb未授权')

def check_redis(ip):
	try:
		redis = StrictRedis(host=ip,port=6379,db=0,password='')
		redis.set('name','BKB')
		print(redis.get('name'))
		print(redis.dbsize())
		click.secho('[+] 存在reids未授权:', fg='red')
	except:
		print('[-] -> 不存在reids未授权')


# 检测是否存在zookeeper未授权漏洞
def check_zookeeper(ip):
	try:
		zk = KazooClient(hosts='{}:{}'.format(ip, 2181))
		zk.start()
		chidlrens = zk.get_children('/')
		if len(chidlrens) > 0:
			click.secho('[+] 存在zookeeper未授权:', fg='red')
		zk.stop()
	except Exception as e:
		# zk.stop()
		# error = e.args
		print('[-] 不存在zookeeper未授权')

def check_elasticsearch(ip):
	port =  9200
	try:
		es = Elasticsearch("{}:{}".format(ip, port), timeout=5)  # 连接Elasticsearch,延时5秒
		es.indices.create(index='unauth_text')
		click.secho('[+] 成功连接elasticsearch', fg='red')
		print('[+] 成功连接 ：{}'.format(ip))
		print('[+] {} -> 成功创建测试节点unauth_text'.format(ip))
		es.index(index="unauth_text", doc_type="test-type", id=2, body={"text": "text"})
		print('[+] {} -> 成功往节点unauth_text插入数据'.format(ip))
		ret = es.get(index="unauth_text", doc_type="test-type", id=2)
		print('[+] {} -> 成功获取节点unauth_text数据 : {}'.format(ip, ret))
		es.indices.delete(index='unauth_text')
		print('[+] {} -> 清除测试节点unauth_text数据'.format(ip))
		print('[ok] {} -> 存在ElasticSearch未授权漏洞'.format(ip))

		print('尝试获取节点信息：↓')
		text = json.loads(requests.get(url='http://{}:{}/_nodes'.format(ip, port), timeout=5).text)
		nodes_total = text['_nodes']['total']
		nodes = list(text['nodes'].keys())
		print('[ok] {} -> [{}] : {}'.format(ip, nodes_total, nodes))

	except Exception as e:
		# error = e.args
		print('[-] 不存在ElasticSearch未授权漏洞')
		# print('[-] -> {} 不存在ElasticSearch未授权漏洞 : {}'.format(ip, error))


def check_ftp(ip):
	try:
		ftp = ftplib.FTP(ip)
		ftp.login('anonymous','guest@guest.com')
		ftp_unauthhost.append(host)
		click.secho('[+] 存在ftp未授权:', fg='red')
	except Exception as e:
		# print(e)
		print('[-] 不存在ftp未授权漏洞')

def check_Memcached(url):
	port = int(url.split(':')[-1]) if ':' in url else 11211
	payload = '\x73\x74\x61\x74\x73\x0a'  # command:stats
	s = socket.socket()
	socket.setdefaulttimeout(10)
	try:
		host = url.split(':')[0]
		s.connect((host, port))
		s.send(payload)
		recvdata = s.recv(2048)  # response larger than 1024
		s.close()
		click.secho('[+] 存在Memcached未授权:', fg='red')
		if recvdata and 'STAT version' in recvdata:
			ans_str = url
			ans_str += ' | version:' + ''.join(re.findall(r'version\s(.*?)\s', recvdata))
			ans_str += ' | total_items:' + ''.join(re.findall(r'total_items\s(\d+)\s', recvdata))
			return ans_str
	except Exception as e:
		# print(e)
		print('[-] 不存在Memcached未授权漏洞')
		pass
	return False


if __name__ == '__main__':
	ip = sys.argv[1]
	check_mongodb(ip)
	check_mongodb1(ip)
	check_redis(ip)
	check_zookeeper(ip)
	check_elasticsearch(ip)
	check_ftp(ip)
	check_Memcached(ip)
