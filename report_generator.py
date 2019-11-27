#!/usr/bin/env python
import argparse
import sys
from time import mktime
from datetime import datetime, date
from collections import Counter
import parsedatetime
from bugzilla import Bugzilla
from terminaltables import SingleTable, AsciiTable
from sqlalchemy import Table, Column, Integer, String, Date, MetaData
from sqlalchemy import create_engine, func, and_, select

SORT_MAP = {
        'urgent': '1',
        'high': '2',
        'medium': '3',
        'low': '4',
        'unspecified': '4',
        'NEW': '1',
        'ASSIGNED': '2',
        'MODIFIED': '3',
        'ON_QA': '4'
        }

TABLES = [
        ('priority', 'Priority'),
        ('status', 'Status'),
        ('severity', 'Severity'),
        ('component', 'Component'),
        ('version', 'Distro Version')
        ]

VALID_BUG_STATUSES = ['NEW', 'ASSIGNED', 'MODIFIED', 'ON_QA']

METADATA = MetaData()
BUG_TABLE = Table('bugs', METADATA,
                  Column('date', Date(), primary_key=True),
                  Column('attribute', String(16), primary_key=True),
                  Column('category', String(32), primary_key=True),
                  Column('owned', Integer),
                  Column('unowned', Integer))

def get_security_bugs():
    bugzilla = Bugzilla(url='https://bugzilla.redhat.com/xmlrpc.cgi')
    query_data = {
        'keywords': 'SecurityTracking',
        'keywords_type': 'allwords',
        # 'component': 'cacti',
        # 'severity': 'high',
        'status': VALID_BUG_STATUSES,
    }
    buglist = bugzilla.query(query_data)
    return buglist

def database(metadata):
    engine = create_engine('sqlite:///sqlite3.db', echo=False)
    metadata.create_all(engine)
    return engine.connect()

def build_table(buglist, attribute):
    # Find count of tickets based on our attribute
    frequency = Counter([getattr(x, attribute) for x in buglist])

    # How many tickets of each type are present?
    owned = {}
    for category in frequency.keys():
        freq = Counter([('fst_owner' in x.status_whiteboard) for x in buglist
                        if getattr(x, attribute) == category])
        owned[category] = freq

    # Let's build rows for the table
    table_rows = []
    for category, total in frequency.items():
        row = [
            category,
            str(total),
            str(owned[category][True]),
            str(owned[category][False])
            ]
        table_rows.append(row)
    return table_rows

def save_table(table_rows, attribute, connection):
    fields = ['date', 'attribute', 'category', 'owned', 'unowned']
    tupels = []
    # row = [category, total, owned, unowned]
    for row in table_rows:
        line = [curdate, attribute, row[0], row[2], row[3]]
        tupels.append(dict(zip(fields, line)))
    connection.execute(BUG_TABLE.insert(), tupels)


def draw_table(table_fields, table_rows, limit=None, previous=False):
    label = table_fields[1]

    # sort to first column
    def sort_key(key):
        if key in SORT_MAP:
            return SORT_MAP[key]
        return key
    if table_fields[0] == 'component':
        ordered_rows = sorted(table_rows, key=lambda t: int(t[1]), reverse=True)
    else:
        ordered_rows = sorted(table_rows, key=lambda t: sort_key(t[0]))

    if limit is not None:
        ordered_rows = ordered_rows[0:limit]

    if previous:
        headers = [label, 'Tickets (delta)', 'Owned (delta)', 'Unowned (delta)']
    else:
        headers = [label, 'Tickets', 'Owned', 'Unowned']
    # Generate the table
    if sys.stdout.isatty():
        return SingleTable(table_data=[headers]+ordered_rows,
                           title="Tickets by {0}".format(label)).table
    return AsciiTable(table_data=[headers]+ordered_rows,
                      title="Tickets by {0}".format(label)).table

def draw_header(datadate):
    # Build Report
    datestring = datetime.now().isoformat(' ')
    datastring = datadate.isoformat()
    return (
        r" __           _\n"
        r"/ _|  ___  __| | ___  _ __ __ _\n"
        r"| |_ / _ \/ _` |/ _ \| '__/ _` |  Fedora Security Team Report\n"
        r"|  _|  __/ (_| | (_) | | | (_| |  Report date: {0}\n"
        r"|_|  \___|\__,_|\___/|_|  \__,_|  Data from: {1}\n"
        r"-------------------------------------------------------------------------------\n"
    ).format(datestring, datastring)

if __name__ == '__main__':
    # pylint: disable=C0103
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('-c', '--cron', action='store_true',
                       help='fetch and store data from bugzilla')
    group.add_argument('-f', '--fetch', action='store_true',
                       help='fetch report from bugzilla')
    group.add_argument('-d', '--date', nargs=1, default=None,
                       help='show tables from specified date (e.g. "2 days'
                            ' ago", "today" or "2015-09-01")')
    parser.add_argument('--show-delta-days', type=int,
                        help='show difference to N days before')
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
        except ValueError as exeption:
            try:
                # parse all human readable dates
                cal = parsedatetime.Calendar()
                time_struct, parse_status = cal.parse(datestr)
                readdate = datetime.fromtimestamp(mktime(time_struct)).date()
            except ValueError as exception:
                parser.error("could not parse specified date.")
    curdate = date.today()

    conn = None
    if not args.fetch:
        conn = database(METADATA)

    if args.cron:
        # Saving bugzilla data to database
        # check if db contains current date - if yes do not collect data
        sel = select([func.count(BUG_TABLE.c.date).label('dates')]).where(BUG_TABLE.c.date == curdate) # pylint: disable=C0301
        if conn.execute(sel).fetchone()[0] == 0:
            bugs = get_security_bugs()
            for table in TABLES:
                rows = build_table(bugs, table[0])
                # Store data
                save_table(rows, table[0], conn)
        else:
            print("Data has been stored already.")
            sys.exit(1)

    elif args.fetch:
        # Fetching live data from Bugzilla
        print(draw_header(datadate=date.today()))
        # Gather data
        bugs = get_security_bugs()
        for table in TABLES:
            rows = build_table(bugs, table[0])
            print(draw_table(table, rows, 10))
            print()

    else:
        # Get data from specific date
        print(draw_header(datadate=readdate))

        for table in TABLES:
            # fetch db table from $readdate
            rows = []
            sel = select(
                [BUG_TABLE.c.category, BUG_TABLE.c.owned, BUG_TABLE.c.unowned]
                ).where(
                    and_(
                        BUG_TABLE.c.date == readdate,
                        BUG_TABLE.c.attribute == table[0]
                        )
                    )
            for elem in conn.execute(sel).fetchall():
                rows.append([elem[0], str(elem[1]+elem[2]), str(elem[1]), str(elem[2])])
            print(draw_table(table, rows, 10))
            print()

    if conn is not None:
        conn.close()
