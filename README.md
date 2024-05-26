# spring-security-3-JWT

We implemented Spring Security in the repo `spring-security-3` here let's start implementing JWT along the spring security.

To authenticate an user we need username and password. So, let's gp ahead and create a method in controller to accept userName and password.

```java
@PostMapping("/authenticate")
  public String authenticateAndGetTken(@RequestBody AuthenticationRequestDetails details) {
    return "";
  }

  @Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationRequestDetails {
    private String username;
    private String password;
}
```

As soon as we get the userName we have to create the token based on the userName, To do that we need a service class.

```java
@Autowired
  private JwtTokenGeneratingService jwtService;

@PostMapping("/authenticate")
  public String authenticateAndGetTken(@RequestBody AuthenticationRequestDetails details) {
    return jwtService.generateToken(details.getUsername());
  }
```

The service class looks like

```java
@Service
public class JwtTokenGeneratingService {

    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, username);
    }

    private String createToken(Map<String, Object> claims, String username) {

    }
}
```

To implement the unImplemented `createToken()` method we need few dependencies from JWT.
