<!DOCTYPE html>
<html>
<head>
    <title>Login Page</title>
</head>
<body>
    <h2>Login Page</h2>
    <c:if test="${param.login == 'false'}">
        <p style="color: red;">Invalid username or password.</p>
    </c:if>
    <form action="LoginServlet" method="post">
        Username: <input type="text" name="username" /><br />
        Password: <input type="password" name="password" /><br />
        <input type="submit" value="Login" />
    </form>
</body>
</html>
