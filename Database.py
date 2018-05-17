from syslog_log import *
try:
    from adodb import adodb
except ImportError:
    try:
        import adodb
    except ImportError:
        critical('You need python adodb module installed')

class DatabaseConn:

    def __init__(self):
        self.__conn = None

    def connect(self, db_type, host, db_name, user, password):
        self.__conn = adodb.NewADOConnection(db_type)
        if password is None:
            password = ''
        try:
            self.__conn.Connect(host, user, password, db_name)
        except Exception as e_message:
            error("Can't connect to database (%s@%s): %s" % (user, host, e_message))
            self.__conn = None

        return self.__conn

    def exec_query(self, query):
        result = ''
        try:
            cursor = self.__conn.Execute(query)
        except Exception as e:
            error('Error executing query (%s)' % e)
            return []

        while not cursor.EOF:
            for r in cursor.fields:
                result += str(r) + ' '

            cursor.MoveNext()

        self.__conn.CommitTrans()
        cursor.Close()
        return result

    def close(self):
        if self.__conn is not None:
            self.__conn.Close()
