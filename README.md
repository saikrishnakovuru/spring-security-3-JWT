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

We know that the JWT token comes with `Header`, `Payload` and `Signature`. let's provide those.

`Subject and Expiration` time are part of `Payload`, that contains `userName and expiration time`.

`Header` and `signature` are being set at the same place `signWith()`

```java
private String createToken(Map<String, Object> claims, String username) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }
```

An important step that could not be ignored is, allowing the `/products/authenticate` without any security issues. Take a look at the `SecurityConfig's securityFilterChain()`

With the implementation we have, we will be able to generate the token to anyOne though he's not an user at all because we are not validating the user details to the details in DB.

// Creating the token in API tool.

```java
http://localhost:8080/products/authenticate

{
  "username":"sai",
  "password":"sai"
}
```

In the springSecurity flow, later FilterChain the request will be deligated to `AuthenticationManager`. Now let's use authentication manager to validate the userDetails for authentication.

```java
@PostMapping("/authenticate")
  public String authenticateAndGetTken(@RequestBody AuthenticationRequestDetails details) {
    Authentication authentication = authenticationManager
        .authenticate(new UsernamePasswordAuthenticationToken(details.getUsername(), details.getPassword()));
    if (authentication.isAuthenticated())
      return jwtService.generateToken(details.getUsername());
    else
      throw new UsernameNotFoundException("invalid user request !");
  }

  //SecurityConfig
  @Bean
  public AuthenticationManager authManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
  }
```

## Token validation

Till now, we created the token, in the further steps we need to validate the token basedon the username, expiration time.

Created a new class 'JwtAuthFilter' to validate the token.

```java
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
              String authHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            username = jwtService.extractUsername(token);
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            if (jwtService.validateToken(token, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails,
                        null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
```

In the above code, we get the token as part of request. So, we now have to validate the token. To validate the token, we need some piece of code in `JwtTokenGeneratingService`.

`Important` step is to set authToken to SecurityContextHolder.

```java
public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
```

We completely imlemented JwtAuthFilter, and we should tell the spring Security to use this instead of its default auth.

So let's go ahead and append this additionally to the SecurityFilterChain in `SecurityConfig` class.

```java
.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authenticationProvider(authenticationProvider())
        .addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class)
        .httpBasic(Customizer.withDefaults())
        .build();
```
