#!/usr/bin/env  python
#-*- coding:utf-8 -*-
from Database import DatabaseConn
from Config import  Conf
from ParserFormattedSnort import SnortEventsParser

class OutputDB():
    def __init__(self, conf):
        self.conf = conf
        type = self.conf.get('output-db', 'type')
        host = self.conf.get('output-db', 'host')
        base = self.conf.get('output-db', 'base')
        user = self.conf.get('output-db', 'user')
        password = self.conf.get('output-db', 'pass')
        self.conn = DatabaseConn()
        self.conn.connect(type, host, base, user, password)
        self.activated = True

    def event(self, e, priority = 0):
        if self.conn is not None and self.activated:
            query= e.to_sql()
            print(query)
            try:
                self.conn.exec_query(query)
            except Exception as e:
                print(': Error executing query (%s)' % e)

        return

    def shutdown(self):
        print('Closing database connection..')
        self.conn.close()
        self.activated = False


class NextNIDS:
   def __init__(self):
       print "init"
       
       
   def run(self):
        conf = Conf()
        conf.read(['config.cfg'],check_neededEntries=False)
        output = OutputDB(conf)
        sep = SnortEventsParser(output)
        sep.process()
        print conf
        
if __name__ == "__main__" :
    NN =NextNIDS()
    NN.run()




