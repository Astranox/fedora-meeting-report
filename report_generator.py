#!/usr/bin/env python
from bugzilla import Bugzilla
from collections import Counter
from datetime import datetime, date
from time import mktime
from terminaltables import SingleTable
from sqlalchemy import create_engine, func, and_, select, Table, Column, Integer, String, Date, MetaData
import parsedatetime
import argparse
import sys

TABLES = [
        ('priority', 'Priority'),
        ('status', 'Status'),
        ('severity', 'Severity'),
        ('component', 'Component'),
        ('version', 'Distro Version')
        ]

metadata = MetaData()
bugtable = Table('bugs', metadata,
    Column('date', Date(), primary_key=True),
    Column('attribute', String(16), primary_key=True),
    Column('category', String(32), primary_key=True),
    Column('owned', Integer),
    Column('unowned', Integer))

def get_security_bugs():
    bz = Bugzilla(url='https://bugzilla.redhat.com/xmlrpc.cgi')
    VALID_STATUSES = ['NEW', 'ASSIGNED', 'MODIFIED', 'ON_QA']
    query_data = {
        'keywords': 'SecurityTracking',
        'keywords_type': 'allwords',
        # 'component': 'cacti',
        # 'severity': 'high',
        'status': VALID_STATUSES,
    }
    bugs = bz.query(query_data)
    return bugs

def database(metadata):
    engine = create_engine('sqlite:///sqlite3.db', echo=False)
    metadata.create_all(engine)
    return engine.connect()

def build_table(bugs, attribute):
    # Find count of tickets based on our attribute
    frequency = Counter([getattr(x, attribute) for x in bugs])

    # How many tickets of each type are present?
    owned = {}
    for category in frequency.keys():
        freq = Counter([('fst_owner' in x.status_whiteboard) for x in bugs
                       if getattr(x, attribute) == category])
        owned[category] = freq

    # Let's build rows for the table
    rows = []
    for category, total in sorted(frequency.items(), key=lambda t: t[1],
                                 reverse=True):
        row = [
            category,
            str(total),
            str(owned[category][True]),
            str(owned[category][False])
            ]
        rows.append(row)
    return rows

def save_table(rows, attribute, conn, table):
    fields = ['date', 'attribute', 'category', 'owned', 'unowned']
    tupels = []
    # row = [category, total, owned, unowned]
    for row in rows:
        line = [curdate, attribute, row[0], row[2], row[3]]
        tupels.append(dict(zip(fields, line)))
    conn.execute(bugtable.insert(), tupels)

def draw_table(rows, label, limit=None, previous=False):
    if limit is not None:
        rows = rows[0:limit]

    if previous:
        headers = [label, 'Tickets (delta)', 'Owned (delta)', 'Unowned (delta)']
    else:
        headers = [label, 'Tickets', 'Owned', 'Unowned']
    # Generate the table
    return SingleTable(table_data=[headers]+rows,
                     title="Tickets by {0}".format(label)).table

def draw_header(datadate):
    # Build Report
    datestring = datetime.now().isoformat(' ')
    datastring = datadate.isoformat()
    return (
    " __           _\n"
    "/ _|  ___  __| | ___  _ __ __ _\n"
    "| |_ / _ \/ _` |/ _ \| '__/ _` |  Fedora Security Team Report\n"
    "|  _|  __/ (_| | (_) | | | (_| |  Report date: {0}\n"
    "|_|  \___|\__,_|\___/|_|  \__,_|  Data from: {1}\n"
    "-------------------------------------------------------------------------------\n"
    ).format(datestring, datastring)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('-c', '--cron', action='store_true', help='fetch and store data from bugzilla')
    group.add_argument('-f', '--fetch', action='store_true', help='fetch report from bugzilla')
    group.add_argument('-d', '--date', nargs=1, default=None, help='show tables from specified date (e.g. "2 days ago", "today" or "2015-09-01")')
    parser.add_argument('--show-delta-days', type=int, help='show difference to N days before')
    args = parser.parse_args()

    if not args.cron and args.date is None:
        # set fetch as default action
        args.fetch = True

    readdate = date.today()
    if args.date is not None:
        datestr = ' '.join(args.date)
        try:
            # parse dates like "2015-09-01"
            readdate = datetime.strptime(datestr, "%Y-%m-%d").date()
        except ValueError as e:
            try:
                # parse all human readable dates
                cal = parsedatetime.Calendar()
                time_struct, parse_status = cal.parse(datestr)
                readdate = datetime.fromtimestamp(mktime(time_struct)).date()
            except ValueError as e:
                parser.error("could not parse specified date.")
    curdate = date.today()

    conn = None
    if not args.fetch:
        conn = database(metadata)

    if args.cron:
        """ Saving bugzilla data to database """
        # check if db contains current date - if yes do not collect data
        sel = select([func.count(bugtable.c.date).label('dates')]).where(bugtable.c.date == curdate)
        if conn.execute(sel).fetchone()[0] == 0:
            bugs = get_security_bugs()
            for table in TABLES:
                rows = build_table(bugs, table[0])
                # Store data
                save_table(rows, table[0], conn, bugtable)
        else:
            print("Data has been stored already.")
            sys.exit(1)

    elif args.fetch:
        """ Fetching live data from Bugzilla """
        print(draw_header(datadate=date.today()))
        # Gather data
        bugs = get_security_bugs()
        for table in TABLES:
            rows = build_table(bugs, table[0])
            print(draw_table(rows, table[1], 10))

    else:
        """ Get data from specific date """
        print(draw_header(datadate=readdate))

        for table in TABLES:
            # fetch db table from $readdate
            rows = []
            sel = select(
                    [bugtable.c.category,bugtable.c.owned, bugtable.c.unowned]
                    ).where(
                            and_(
                                bugtable.c.date == readdate,
                                bugtable.c.attribute == table[0]
                                )
                            )
            for elem in conn.execute(sel).fetchall():
                rows.append([elem[0], str(elem[1]+elem[2]), str(elem[1]), str(elem[2])])
            print(draw_table(rows, table[1], 10))

    if conn is not None:
        conn.close()
