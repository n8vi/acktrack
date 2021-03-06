Imports System.Net
Imports System.Net.Sockets
Imports System.Text
Imports System.Runtime.InteropServices


Module Module1


    <DllImport("acktrack.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Function acktrack_openlog(ByVal logfile As String) As Boolean
    End Function
    <DllImport("acktrack.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Sub acktrack_writelog(msg As String)
    End Sub
    <DllImport("acktrack.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Sub acktrack_closelog()
    End Sub
    <DllImport("acktrack.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Function acktrack_error() As String
    End Function

    <DllImport("acktrack.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Function acktrack_create_fromstrings(ByVal LocalEndPointStr As String, ByVal RemoteEndPointStr As String) As IntPtr
    End Function
    <DllImport("acktrack.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Function acktrack_isfinished(ByVal cs As IntPtr) As Boolean
    End Function
    <DllImport("acktrack.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Function acktrack_next(acktrack As IntPtr) As IntPtr
    End Function
    <DllImport("acktrack.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Function acktrack_se_ts_sec(ByVal se As IntPtr) As Integer
    End Function
    <DllImport("acktrack.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Function acktrack_se_ts_usec(ByVal se As IntPtr) As Integer
    End Function
    <DllImport("acktrack.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Function acktrack_se_is_local(ByVal se As IntPtr) As Boolean
    End Function
    <DllImport("acktrack.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Function acktrack_se_seqno(ByVal se As IntPtr) As Integer
    End Function
    <DllImport("acktrack.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Function acktrack_se_is_interesting(ByVal se As IntPtr) As Boolean
    End Function
    <DllImport("acktrack.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Function acktrack_se_is_error(ByVal se As IntPtr) As Boolean
    End Function

    ' string result = String.Format("{0,10:D6} {0,10:X8}", value);

    Sub printpkt(se As IntPtr)
        If (se) Then

            If acktrack_se_is_interesting(se) Then
                If acktrack_se_is_local(se) Then
                    Console.WriteLine(String.Format(" --> SEQ {0:D}.{1:D6} {2}", acktrack_se_ts_sec(se), acktrack_se_ts_usec(se), acktrack_se_seqno(se)))
                Else
                    Console.WriteLine(String.Format(" <-- ACK {0:D}.{1:D6} {2}", acktrack_se_ts_sec(se), acktrack_se_ts_usec(se), acktrack_se_seqno(se)))
                End If
            End If
        End If
    End Sub


    Sub Main()
        Dim socket As Socket
        Dim port As Int32 = 80
        Dim host As String = "google.com"
        Dim request As String = "GET /" + vbNewLine
        Dim bytesReceived() As Byte
        Dim bytesSent() As Byte = Encoding.ASCII.GetBytes(request)
        Dim cs As IntPtr
        Dim se As IntPtr
        Dim utcnow = DateTime.UtcNow
        Dim span As TimeSpan
        Dim ret As Integer

        ret = acktrack_openlog("C:\Users\Public\Documents\acktrack.txt")

        If Not ret Then
            Console.Write("Error opening log C:\Users\Public\Documents\acktrack.txt: ")
            Console.WriteLine(acktrack_error())
        End If


        socket = createSocket(host, port)

        Console.Write(socket.LocalEndPoint.ToString())
        Console.Write(" ==> ")
        Console.WriteLine(socket.RemoteEndPoint.ToString())

        cs = acktrack_create_fromstrings(socket.LocalEndPoint.ToString(), socket.RemoteEndPoint.ToString())

        If socket IsNot Nothing Then
            Console.WriteLine("Socket connected!")

            socket.Send(bytesSent, bytesSent.Length, 0)

            Console.WriteLine("sent bytes.")

            acktrack_writelog("starting while loop")
            While Not acktrack_isfinished(cs)
                acktrack_writelog("cycling through while loop, about to call acktrack_next")
                se = acktrack_next(cs)
                acktrack_writelog("called acktrack_next")
                printpkt(se)
                span = DateTime.UtcNow - utcnow
                If socket.Connected And (span > TimeSpan.FromSeconds(3)) Then
                    showRx(socket)
                    Console.WriteLine("Closing socket")
                    socket.Close()
                End If
            End While
        Else
            Console.WriteLine("Socket not connected.")
        End If
        'Console.WriteLine("Connection terminated.  Press key to exit.")
        'Console.ReadKey()

    End Sub

    Public Function createSocket(ByVal server As String, ByVal port As Int32) As Socket
        Dim hostEntry As IPHostEntry
        Try
            hostEntry = Dns.GetHostEntry(server)
        Catch e As SocketException
            Console.WriteLine("host not found")
            Return Nothing
        End Try

        For Each ipaddress In hostEntry.AddressList
            Dim ipe As IPEndPoint
            Try
                ipe = New IPEndPoint(System.Net.IPAddress.Parse(server), port)
            Catch
                ipe = New IPEndPoint(ipaddress, port)
            End Try

            If ipe.AddressFamily <> AddressFamily.InterNetwork Then
                Continue For
            End If


            Dim sock As Socket = New Socket(ipe.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
            Console.WriteLine("Connecting to {0}:{1}", server, port)
            sock.Connect(ipe)

            If sock.Connected Then
                Return sock
            Else
                Return Nothing
            End If
        Next
    End Function

    Public Sub showRx(sock As Socket)
        Dim len As Integer
        Dim inBytes() As Byte

        len = sock.Available()
        ReDim inBytes(len)
        Console.Write(len)
        Console.WriteLine(" bytes received.")
        sock.Receive(inBytes, SocketFlags.None)
    End Sub

End Module
