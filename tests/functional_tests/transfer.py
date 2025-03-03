#!/usr/bin/env python3

# Copyright (c) 2019 The Monero Project
# 
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import print_function
import json

"""Test simple transfers
"""

from framework.daemon import Daemon
from framework.wallet import Wallet

class TransferTest():
""" Test transfer RPC calls

Test for the following RPC calls:
    - get_balance
    - transfer
"""
import time
from time import sleep

from test_framework.daemon import Daemon
from test_framework.wallet import Wallet

mainnet_address_1 = '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'

mainnet_address_2 = '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'

class AbelianTransferTest():
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        self.reset()
        self.create()
        self.mine()
        self.transfer()
        self.check_get_bulk_payments()
        self.check_double_spend_detection()
        self.sweep_single()

    def reset(self):
        print('Resetting blockchain')

    def reset(self):
        print('Reset Abelian Blockchain')
        daemon = Daemon()
        daemon.pop_blocks(1000)
        daemon.flush_txpool()

    def create(self):
        print('Creating wallets')
        seeds = [
          'velvet lymph giddy number token physics poetry unquoted nibs useful sabotage limits benches lifestyle eden nitrogen anvil fewest avoid batch vials washing fences goat unquoted',
          'peeled mixture ionic radar utopia puddle buying illness nuns gadget river spout cavernous bounced paradise drunk looking cottage jump tequila melting went winter adjust spout',
          'dilute gutter certain antics pamphlet macro enjoy left slid guarded bogeys upload nineteen bomb jubilee enhanced irritate turnip eggs swung jukebox loudly reduce sedan slid',
        ]
        self.wallet = [None] * len(seeds)
        for i in range(len(seeds)):
            self.wallet[i] = Wallet(idx = i)
            # close the wallet if any, will throw if none is loaded
            try: self.wallet[i].close_wallet()
            except: pass
            res = self.wallet[i].restore_deterministic_wallet(seed = seeds[i])

    def mine(self):
        print("Mining some blocks")
        daemon = Daemon()

        res = daemon.get_info()
        height = res.height

        daemon.generateblocks('42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm', 80)
        for i in range(len(self.wallet)):
            self.wallet[i].refresh()
            res = self.wallet[i].get_height()
            assert res.height == height + 80

    def transfer(self):
        daemon = Daemon()

        print("Creating transfer to self")

        dst = {'address': '42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm', 'amount': 1000000000000}
        payment_id = '1234500000012345abcde00000abcdeff1234500000012345abcde00000abcde'

        start_balances = [0] * len(self.wallet)
        running_balances = [0] * len(self.wallet)
        for i in range(len(self.wallet)):
          res = self.wallet[i].get_balance()
          start_balances[i] = res.balance
          running_balances[i] = res.balance
          assert res.unlocked_balance <= res.balance
          if i == 0:
            assert res.blocks_to_unlock == 59 # we've been mining to it
          else:
            assert res.blocks_to_unlock == 0

        print ('Checking short payment IDs cannot be used when not in an integrated address')
        ok = False
        try: self.wallet[0].transfer([dst], ring_size = 11, payment_id = '1234567812345678', get_tx_key = False)
        except: ok = True
        assert ok

        print ('Checking empty destination is rejected')
        ok = False
        try: self.wallet[0].transfer([], ring_size = 11, get_tx_key = False)
        except: ok = True
        assert ok

        res = self.wallet[0].transfer([dst], ring_size = 11, payment_id = payment_id, get_tx_key = False)
        assert len(res.tx_hash) == 32*2
        txid = res.tx_hash
        assert len(res.tx_key) == 0
        assert res.amount > 0
        amount = res.amount
        assert res.fee > 0
        fee = res.fee
        assert len(res.tx_blob) == 0
        assert len(res.tx_metadata) == 0
        assert len(res.multisig_txset) == 0
        assert len(res.unsigned_txset) == 0
        unsigned_txset = res.unsigned_txset

        self.wallet[0].refresh()

        res = daemon.get_info()
        height = res.height

        res = self.wallet[0].get_transfers()
        assert len(res['in']) == height - 1 # coinbases
        assert not 'out' in res or len(res.out) == 0 # not mined yet
        assert len(res.pending) == 1
        assert not 'pool' in res or len(res.pool) == 0
        assert not 'failed' in res or len(res.failed) == 0
        for e in res['in']:
          assert e.type == 'block'
        e = res.pending[0]
        assert e.txid == txid
        assert e.payment_id == payment_id
        assert e.type == 'pending'
        assert e.unlock_time == 0
        assert e.subaddr_index.major == 0
        assert e.subaddr_indices == [{'major': 0, 'minor': 0}]
        assert e.address == '42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm'
        assert e.double_spend_seen == False
        assert e.confirmations == 0

        running_balances[0] -= 1000000000000 + fee

        res = self.wallet[0].get_balance()
        assert res.balance == running_balances[0]
        assert res.unlocked_balance <= res.balance
        assert res.blocks_to_unlock == 59

        daemon.generateblocks('42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm', 1)
        res = daemon.getlastblockheader()
        running_balances[0] += res.block_header.reward
        self.wallet[0].refresh()

        running_balances[0] += 1000000000000

        res = self.wallet[0].get_transfers()
        assert len(res['in']) == height # coinbases
        assert len(res.out) == 1 # not mined yet
        assert not 'pending' in res or len(res.pending) == 0
        assert not 'pool' in res or len(res.pool) == 0
        assert not 'failed' in res or len(res.failed) == 0
        for e in res['in']:
          assert e.type == 'block'
        e = res.out[0]
        assert e.txid == txid
        assert e.payment_id == payment_id
        assert e.type == 'out'
        assert e.unlock_time == 0
        assert e.subaddr_index.major == 0
        assert e.subaddr_indices == [{'major': 0, 'minor': 0}]
        assert e.address == '42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm'
        assert e.double_spend_seen == False
        assert e.confirmations == 1

        res = self.wallet[0].get_height()
        wallet_height = res.height
        res = self.wallet[0].get_transfer_by_txid(txid)
        assert len(res.transfers) == 1
        assert res.transfers[0] == res.transfer
        t = res.transfer
        assert t.txid == txid
        assert t.payment_id == payment_id
        assert t.height == wallet_height - 1
        assert t.timestamp > 0
        assert t.amount == 0 # to self, so it's just "pay a fee" really
        assert t.fee == fee
        assert t.note == ''
        assert len(t.destinations) == 1
        assert t.destinations[0] == {'address': '42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm', 'amount': 1000000000000}
        assert t.type == 'out'
        assert t.unlock_time == 0
        assert t.address == '42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm'
        assert t.double_spend_seen == False
        assert t.confirmations == 1

        res = self.wallet[0].get_balance()
        assert res.balance == running_balances[0]
        assert res.unlocked_balance <= res.balance
        assert res.blocks_to_unlock == 59

        print("Creating transfer to another, manual relay")

        dst = {'address': '44Kbx4sJ7JDRDV5aAhLJzQCjDz2ViLRduE3ijDZu3osWKBjMGkV1XPk4pfDUMqt1Aiezvephdqm6YD19GKFD9ZcXVUTp6BW', 'amount': 1000000000000}
        res = self.wallet[0].transfer([dst], ring_size = 11, payment_id = payment_id, get_tx_key = True, do_not_relay = True, get_tx_hex = True)
        assert len(res.tx_hash) == 32*2
        txid = res.tx_hash
        assert len(res.tx_key) == 32*2
        assert res.amount == 1000000000000
        amount = res.amount
        assert res.fee > 0
        fee = res.fee
        assert len(res.tx_blob) > 0
        assert len(res.tx_metadata) == 0
        assert len(res.multisig_txset) == 0
        assert len(res.unsigned_txset) == 0
        tx_blob = res.tx_blob

        res = daemon.send_raw_transaction(tx_blob)
        assert res.not_relayed == False
        assert res.low_mixin == False
        assert res.double_spend == False
        assert res.invalid_input == False
        assert res.invalid_output == False
        assert res.too_big == False
        assert res.overspend == False
        assert res.fee_too_low == False
        assert res.not_rct == False

        self.wallet[0].refresh()

        res = self.wallet[0].get_balance()
        assert res.balance == running_balances[0]
        assert res.unlocked_balance <= res.balance
        assert res.blocks_to_unlock == 59

        self.wallet[1].refresh()

        res = self.wallet[1].get_transfers()
        assert not 'in' in res or len(res['in']) == 0
        assert not 'out' in res or len(res.out) == 0
        assert not 'pending' in res or len(res.pending) == 0
        assert len(res.pool) == 1
        assert not 'failed' in res or len(res.failed) == 0
        e = res.pool[0]
        assert e.txid == txid
        assert e.payment_id == payment_id
        assert e.type == 'pool'
        assert e.unlock_time == 0
        assert e.subaddr_index.major == 0
        assert e.subaddr_indices == [{'major': 0, 'minor': 0}]
        assert e.address == '44Kbx4sJ7JDRDV5aAhLJzQCjDz2ViLRduE3ijDZu3osWKBjMGkV1XPk4pfDUMqt1Aiezvephdqm6YD19GKFD9ZcXVUTp6BW'
        assert e.double_spend_seen == False
        assert e.confirmations == 0
        assert e.amount == amount
        assert e.fee == fee

        daemon.generateblocks('42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm', 1)
        res = daemon.getlastblockheader()
        running_balances[0] -= 1000000000000 + fee
        running_balances[0] += res.block_header.reward
        self.wallet[1].refresh()
        running_balances[1] += 1000000000000

        res = self.wallet[1].get_transfers()
        assert len(res['in']) == 1
        assert not 'out' in res or len(res.out) == 0
        assert not 'pending' in res or len(res.pending) == 0
        assert not 'pool' in res or len(res.pool) == 0
        assert not 'failed' in res or len(res.failed) == 0
        e = res['in'][0]
        assert e.txid == txid
        assert e.payment_id == payment_id
        assert e.type == 'in'
        assert e.unlock_time == 0
        assert e.subaddr_index.major == 0
        assert e.subaddr_indices == [{'major': 0, 'minor': 0}]
        assert e.address == '44Kbx4sJ7JDRDV5aAhLJzQCjDz2ViLRduE3ijDZu3osWKBjMGkV1XPk4pfDUMqt1Aiezvephdqm6YD19GKFD9ZcXVUTp6BW'
        assert e.double_spend_seen == False
        assert e.confirmations == 1
        assert e.amount == amount
        assert e.fee == fee

        res = self.wallet[1].get_balance()
        assert res.balance == running_balances[1]
        assert res.unlocked_balance <= res.balance
        assert res.blocks_to_unlock == 9

        print('Creating multi out transfer')

        self.wallet[0].refresh()

        dst0 = {'address': '42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm', 'amount': 1000000000000}
        dst1 = {'address': '44Kbx4sJ7JDRDV5aAhLJzQCjDz2ViLRduE3ijDZu3osWKBjMGkV1XPk4pfDUMqt1Aiezvephdqm6YD19GKFD9ZcXVUTp6BW', 'amount': 1100000000000}
        dst2 = {'address': '46r4nYSevkfBUMhuykdK3gQ98XDqDTYW1hNLaXNvjpsJaSbNtdXh1sKMsdVgqkaihChAzEy29zEDPMR3NHQvGoZCLGwTerK', 'amount': 1200000000000}
        res = self.wallet[0].transfer([dst0, dst1, dst2], ring_size = 11, payment_id = payment_id, get_tx_key = True)
        assert len(res.tx_hash) == 32*2
        txid = res.tx_hash
        assert len(res.tx_key) == 32*2
        assert res.amount == 1000000000000 + 1100000000000 + 1200000000000
        amount = res.amount
        assert res.fee > 0
        fee = res.fee
        assert len(res.tx_blob) == 0
        assert len(res.tx_metadata) == 0
        assert len(res.multisig_txset) == 0
        assert len(res.unsigned_txset) == 0
        unsigned_txset = res.unsigned_txset

        running_balances[0] -= 1000000000000 + 1100000000000 + 1200000000000 + fee

        res = self.wallet[0].get_balance()
        assert res.balance == running_balances[0]
        assert res.unlocked_balance <= res.balance
        assert res.blocks_to_unlock == 59

        daemon.generateblocks('42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm', 1)
        res = daemon.getlastblockheader()
        running_balances[0] += res.block_header.reward
        running_balances[0] += 1000000000000
        running_balances[1] += 1100000000000
        running_balances[2] += 1200000000000
        self.wallet[0].refresh()

        res = self.wallet[0].get_transfers()
        assert len(res['in']) == height + 2
        assert len(res.out) == 3
        assert not 'pending' in res or len(res.pending) == 0
        assert not 'pool' in res or len(res.pool) == 1
        assert not 'failed' in res or len(res.failed) == 0
        e = [o for o in res.out if o.txid == txid]
        assert len(e) == 1
        e = e[0]
        assert e.txid == txid
        assert e.payment_id == payment_id
        assert e.type == 'out'
        assert e.unlock_time == 0
        assert e.subaddr_index.major == 0
        assert e.subaddr_indices == [{'major': 0, 'minor': 0}]
        assert e.address == '42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm'
        assert e.double_spend_seen == False
        assert e.confirmations == 1

        assert e.amount == amount
        assert e.fee == fee

        res = self.wallet[0].get_balance()
        assert res.balance == running_balances[0]
        assert res.unlocked_balance <= res.balance
        assert res.blocks_to_unlock == 59

        self.wallet[1].refresh()
        res = self.wallet[1].get_transfers()
        assert len(res['in']) == 2
        assert not 'out' in res or len(res.out) == 0
        assert not 'pending' in res or len(res.pending) == 0
        assert not 'pool' in res or len(res.pool) == 0
        assert not 'failed' in res or len(res.failed) == 0
        e = [o for o in res['in'] if o.txid == txid]
        assert len(e) == 1
        e = e[0]
        assert e.txid == txid
        assert e.payment_id == payment_id
        assert e.type == 'in'
        assert e.unlock_time == 0
        assert e.subaddr_index.major == 0
        assert e.subaddr_indices == [{'major': 0, 'minor': 0}]
        assert e.address == '44Kbx4sJ7JDRDV5aAhLJzQCjDz2ViLRduE3ijDZu3osWKBjMGkV1XPk4pfDUMqt1Aiezvephdqm6YD19GKFD9ZcXVUTp6BW'
        assert e.double_spend_seen == False
        assert e.confirmations == 1
        assert e.amount == 1100000000000
        assert e.fee == fee

        res = self.wallet[1].get_balance()
        assert res.balance == running_balances[1]
        assert res.unlocked_balance <= res.balance
        assert res.blocks_to_unlock == 9

        self.wallet[2].refresh()
        res = self.wallet[2].get_transfers()
        assert len(res['in']) == 1
        assert not 'out' in res or len(res.out) == 0
        assert not 'pending' in res or len(res.pending) == 0
        assert not 'pool' in res or len(res.pool) == 0
        assert not 'failed' in res or len(res.failed) == 0
        e = [o for o in res['in'] if o.txid == txid]
        assert len(e) == 1
        e = e[0]
        assert e.txid == txid
        assert e.payment_id == payment_id
        assert e.type == 'in'
        assert e.unlock_time == 0
        assert e.subaddr_index.major == 0
        assert e.subaddr_indices == [{'major': 0, 'minor': 0}]
        assert e.address == '46r4nYSevkfBUMhuykdK3gQ98XDqDTYW1hNLaXNvjpsJaSbNtdXh1sKMsdVgqkaihChAzEy29zEDPMR3NHQvGoZCLGwTerK'
        assert e.double_spend_seen == False
        assert e.confirmations == 1
        assert e.amount == 1200000000000
        assert e.fee == fee

        res = self.wallet[2].get_balance()
        assert res.balance == running_balances[2]
        assert res.unlocked_balance <= res.balance
        assert res.blocks_to_unlock == 9

        print('Sending to integrated address')
        self.wallet[0].refresh()
        res = self.wallet[0].get_balance()
        i_pid = '1111111122222222'
        res = self.wallet[0].make_integrated_address(standard_address = '44Kbx4sJ7JDRDV5aAhLJzQCjDz2ViLRduE3ijDZu3osWKBjMGkV1XPk4pfDUMqt1Aiezvephdqm6YD19GKFD9ZcXVUTp6BW', payment_id = i_pid)
        i_address = res.integrated_address
        res = self.wallet[0].transfer([{'address': i_address, 'amount': 200000000}])
        assert len(res.tx_hash) == 32*2
        i_txid = res.tx_hash
        assert len(res.tx_key) == 32*2
        assert res.amount == 200000000
        i_amount = res.amount
        assert res.fee > 0
        fee = res.fee
        assert len(res.tx_blob) == 0
        assert len(res.tx_metadata) == 0
        assert len(res.multisig_txset) == 0
        assert len(res.unsigned_txset) == 0

        running_balances[0] -= 200000000 + fee

        res = self.wallet[0].get_balance()
        assert res.balance == running_balances[0]
        assert res.unlocked_balance <= res.balance
        assert res.blocks_to_unlock == 59

        daemon.generateblocks('42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm', 1)
        res = daemon.getlastblockheader()
        running_balances[0] += res.block_header.reward
        running_balances[1] += 200000000

        self.wallet[0].refresh()
        res = self.wallet[0].get_balance()
        assert res.balance == running_balances[0]
        assert res.unlocked_balance <= res.balance
        assert res.blocks_to_unlock == 59

        self.wallet[1].refresh()
        res = self.wallet[1].get_balance()
        assert res.balance == running_balances[1]
        assert res.unlocked_balance <= res.balance
        assert res.blocks_to_unlock == 9

        self.wallet[2].refresh()
        res = self.wallet[2].get_balance()
        assert res.balance == running_balances[2]
        assert res.unlocked_balance <= res.balance
        assert res.blocks_to_unlock == 8

        daemon.generateblocks('42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm', 1)
        res = daemon.getlastblockheader()
        running_balances[0] += res.block_header.reward

        self.wallet[0].refresh()
        res = self.wallet[0].get_balance()
        assert res.balance == running_balances[0]
        assert res.unlocked_balance <= res.balance
        assert res.blocks_to_unlock == 59

        self.wallet[1].refresh()
        res = self.wallet[1].get_balance()
        assert res.balance == running_balances[1]
        assert res.unlocked_balance <= res.balance
        assert res.blocks_to_unlock == 8

        self.wallet[2].refresh()
        res = self.wallet[2].get_balance()
        assert res.balance == running_balances[2]
        assert res.unlocked_balance <= res.balance
        assert res.blocks_to_unlock == 7


    def check_get_bulk_payments(self):
        print('Checking get_bulk_payments')

        daemon = Daemon()
        res = daemon.get_info()
        height = res.height

        self.wallet[0].refresh()
        res = self.wallet[0].get_bulk_payments()
        assert len(res.payments) >= 83 # at least 83 coinbases
        res = self.wallet[0].get_bulk_payments(payment_ids = ['1234500000012345abcde00000abcdeff1234500000012345abcde00000abcde'])
        assert 'payments' not in res or len(res.payments) == 0
        res = self.wallet[0].get_bulk_payments(min_block_height = height)
        assert 'payments' not in res or len(res.payments) == 0
        res = self.wallet[0].get_bulk_payments(min_block_height = height - 40)
        assert len(res.payments) >= 39 # coinbases

        self.wallet[1].refresh()
        res = self.wallet[1].get_bulk_payments()
        assert len(res.payments) >= 3 # two txes to standard address were sent, plus one to integrated address
        res = self.wallet[1].get_bulk_payments(payment_ids = ['1234500000012345abcde00000abcdeff1234500000012345abcde00000abcde'])
        assert len(res.payments) >= 2 # two txes were sent with that payment id
        res = self.wallet[1].get_bulk_payments(payment_ids = ['ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'])
        assert 'payments' not in res or len(res.payments) == 0 # none with that payment id
        res = self.wallet[1].get_bulk_payments(payment_ids = ['1111111122222222' + '0'*48])
        assert len(res.payments) >= 1 # one tx to integrated address

        self.wallet[2].refresh()
        res = self.wallet[2].get_bulk_payments()
        assert len(res.payments) >= 1 # one tx was sent
        res = self.wallet[2].get_bulk_payments(payment_ids = ['1'*64, '1234500000012345abcde00000abcdeff1234500000012345abcde00000abcde', '2'*64])
        assert len(res.payments) >= 1 # one tx was sent

        res = self.wallet[1].get_bulk_payments(["1111111122222222"])
        assert len(res.payments) >= 1 # we have one of these

    def check_double_spend_detection(self):
        print('Checking double spend detection')
        txes = [[None, None], [None, None]]
        for i in range(2):
            self.wallet[0].restore_deterministic_wallet(seed = 'velvet lymph giddy number token physics poetry unquoted nibs useful sabotage limits benches lifestyle eden nitrogen anvil fewest avoid batch vials washing fences goat unquoted')
            self.wallet[0].refresh()
            res = self.wallet[0].get_balance()
            unlocked_balance = res.unlocked_balance
            res = self.wallet[0].sweep_all(address = '44Kbx4sJ7JDRDV5aAhLJzQCjDz2ViLRduE3ijDZu3osWKBjMGkV1XPk4pfDUMqt1Aiezvephdqm6YD19GKFD9ZcXVUTp6BW', do_not_relay = True, get_tx_hex = True)
            assert len(res.tx_hash_list) == 1
            assert len(res.tx_hash_list[0]) == 32*2
            txes[i][0] = res.tx_hash_list[0]
            assert len(res.fee_list) == 1
            assert res.fee_list[0] > 0
            assert len(res.amount_list) == 1
            assert res.amount_list[0] == unlocked_balance - res.fee_list[0]
            assert len(res.tx_blob_list) > 0
            assert len(res.tx_blob_list[0]) > 0
            assert not 'tx_metadata_list' in res or len(res.tx_metadata_list) == 0
            assert not 'multisig_txset' in res or len(res.multisig_txset) == 0
            assert not 'unsigned_txset' in res or len(res.unsigned_txset) == 0
            assert len(res.tx_blob_list) == 1
            txes[i][1] = res.tx_blob_list[0]

        daemon = Daemon()
        res = daemon.send_raw_transaction(txes[0][1])
        assert res.not_relayed == False
        assert res.low_mixin == False
        assert res.double_spend == False
        assert res.invalid_input == False
        assert res.invalid_output == False
        assert res.too_big == False
        assert res.overspend == False
        assert res.fee_too_low == False
        assert res.not_rct == False

        res = daemon.get_transactions([txes[0][0]])
        assert len(res.txs) >= 1
        tx = [tx for tx in res.txs if tx.tx_hash == txes[0][0]][0]
        assert tx.in_pool
        assert not tx.double_spend_seen

        res = daemon.send_raw_transaction(txes[1][1])
        assert res.not_relayed == False
        assert res.low_mixin == False
        assert res.double_spend == True
        assert res.invalid_input == False
        assert res.invalid_output == False
        assert res.too_big == False
        assert res.overspend == False
        assert res.fee_too_low == False
        assert res.not_rct == False

        res = daemon.get_transactions([txes[0][0]])
        assert len(res.txs) >= 1
        tx = [tx for tx in res.txs if tx.tx_hash == txes[0][0]][0]
        assert tx.in_pool
        assert tx.double_spend_seen

    def sweep_single(self):
        daemon = Daemon()

        print("Sending single output")

        daemon.generateblocks('42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm', 1)
        self.wallet[0].refresh()
        res = self.wallet[0].incoming_transfers(transfer_type = 'available')
        for t in res.transfers:
            assert not t.spent
        assert len(res.transfers) > 8 # we mined a lot
        index = 8
        assert not res.transfers[index].spent
        assert res.transfers[index].amount > 0
        ki = res.transfers[index].key_image
        amount = res.transfers[index].amount
        daemon.generateblocks('42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm', 10) # ensure unlocked
        self.wallet[0].refresh()
        res = self.wallet[0].get_balance()
        balance = res.balance
        res = self.wallet[0].incoming_transfers(transfer_type = 'all')
        res = self.wallet[0].sweep_single('44Kbx4sJ7JDRDV5aAhLJzQCjDz2ViLRduE3ijDZu3osWKBjMGkV1XPk4pfDUMqt1Aiezvephdqm6YD19GKFD9ZcXVUTp6BW', key_image = ki)
        assert len(res.tx_hash) == 64
        tx_hash = res.tx_hash
        daemon.generateblocks('44Kbx4sJ7JDRDV5aAhLJzQCjDz2ViLRduE3ijDZu3osWKBjMGkV1XPk4pfDUMqt1Aiezvephdqm6YD19GKFD9ZcXVUTp6BW', 1)
        self.wallet[0].refresh()
        res = self.wallet[0].get_balance()
        new_balance = res.balance
        res = daemon.get_transactions([tx_hash], decode_as_json = True)
        assert len(res.txs) == 1
        tx = res.txs[0]
        assert tx.tx_hash == tx_hash
        assert not tx.in_pool
        assert len(tx.as_json) > 0
        try:
            j = json.loads(tx.as_json)
        except:
            j = None
        assert j
        assert new_balance == balance - amount
        assert len(j['vin']) == 1
        assert j['vin'][0]['key']['k_image'] == ki
        self.wallet[0].refresh()
        res = self.wallet[0].incoming_transfers(transfer_type = 'available')
        assert len([t for t in res.transfers if t.key_image == ki]) == 0
        res = self.wallet[0].incoming_transfers(transfer_type = 'unavailable')
        assert len([t for t in res.transfers if t.key_image == ki]) == 1


if __name__ == '__main__':
    TransferTest().run_test()
        self.wallet = [None] * len(wallet_seeds)
        for i in range(0, len(wallet_seeds)):
            self.wallet[i] = Wallet(idx = i)
            try: self.wallet[i].close_wallet()
            except: pass
            res = self.wallet[i].restore_deterministic_wallet(seed = wallet_seeds[i])
        daemon = Daemon()
        wallet = Wallet()

        destination = wallet.make_uniform_destinations(
            mainnet_address_2, 1)

        # Pre-mining
        self.mine(daemon=daemon, blocks=100)

        # Start Transfer - 1
        self.transfer_100(wallet, count=10)
        self.mine(daemon=daemon, blocks=100)
        
        self.transfer_100(wallet, count=100)
        self.mine(daemon=daemon, blocks=100)
        
        self.transfer_100(wallet, count=1000)
        self.mine(daemon=daemon, blocks=100)

        # Start Transfer - 2
        #self.transfer_100_random(wallet)
        #self.mine(daemon=daemon, blocks=10)

    def mine(self, daemon, blocks):
        print("Mining some blocks")
        start = time.time()
        daemon.generateblocks(mainnet_address_1, blocks)
        print('Generating 500 blocks took: ', time.time() - start, 'seconds')

    def transfer_100(self, wallet, count):
        print("Initiating 100 transfers(1 ABE)")

        start = time.time()

        dest = wallet.make_uniform_destinations(mainnet_address_2, 1)
        for x in range (0, count):
            while wallet.get_balance()['unlocked_balance'] == 0:
                print('Waiting for wallet to refresh...')
                sleep(1)
            print('Sending % 2d transaction' % (x))
            res = wallet.transfer(dest, 1)
            print(res)

        print('Balance: %2d' % wallet.get_balance()['unlocked_balance'])
        print('Transfer tx took: ', time.time() - start, 'seconds')

    def transfer_100_random(self, wallet):
        print("Initiating 100 transfers(10, 100, 1000 ABE)")

        start = time.time()

        dest_10 = wallet.make_uniform_destinations(mainnet_address_2, 10)
        dest_100 = wallet.make_uniform_destinations(mainnet_address_2, 100)
        dest_1000 = wallet.make_uniform_destinations(mainnet_address_2, 1000)

        for x in range (0, 10):
            while wallet.get_balance()['unlocked_balance'] == 0:
                print('Waiting for wallet to refresh...')
                sleep(1)

            print('Sending % 2d transaction' % (x))
            res = wallet.transfer(dest_10, 1)
            print(res)

            res = wallet.transfer(dest_100, 1)
            print(res)

            res = wallet.transfer(dest_1000)
            print(res)

        print('Transfer tx took: ', time.time() - start, 'seconds')



if __name__ == '__main__':
    AbelianTransferTest().run_test()

