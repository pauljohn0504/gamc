"""CLI utility to create an administrator, without a hard-coded default password."""
import argparse
from getpass import getpass
from app import getone,execute,hash_password,now

p=argparse.ArgumentParser(description='GAMC administration helper')
p.add_argument('command',choices=['create-admin'])
p.add_argument('--email',required=True)
p.add_argument('--name',default='GAMC Administrator')
args=p.parse_args()
email=args.email.strip().lower()
if getone('SELECT id FROM users WHERE email=?',(email,)):
    raise SystemExit('That email already exists. No changes made.')
password=getpass('New admin password (minimum 12 characters): ')
if len(password)<12:raise SystemExit('Password too short.')
repeat=getpass('Repeat admin password: ')
if password!=repeat:raise SystemExit('Passwords do not match.')
uid=execute("INSERT INTO users(email,password_hash,display_name,locale,role,onboarded,accepted_terms_at,created_at) VALUES(?,?,?,'ko','admin',1,?,?)",
            (email,hash_password(password),args.name,now(),now()))
print('Administrator created with ID:',uid)
