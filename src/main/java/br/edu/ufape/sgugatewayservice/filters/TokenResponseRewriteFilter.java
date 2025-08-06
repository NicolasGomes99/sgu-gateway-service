package br.edu.ufape.sgugatewayservice.filters;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.NonNull;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.*;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
public class TokenResponseRewriteFilter implements GlobalFilter, Ordered {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        HttpMethod method = exchange.getRequest().getMethod();

        // Fluxo de refresh: sobrescreve request e aplica decorator de resposta
        if (method == HttpMethod.POST && path.matches(".*/auth/refresh$")) {
            HttpCookie cookie = exchange.getRequest().getCookies().getFirst("refreshToken");
            String refresh = (cookie != null ? cookie.getValue() : "");

            String form = "grant_type=refresh_token&refresh_token=" +
                    URLEncoder.encode(refresh, StandardCharsets.UTF_8);
            ServerHttpRequest mutatedRequest = getServerHttpRequest(exchange, form);

            return chain.filter(exchange.mutate()
                    .request(mutatedRequest)
                    .response(getResponseDecorator(exchange))
                    .build());
        }

        // Fluxo de logout
        if (method == HttpMethod.POST && path.matches(".*/auth/logout$")) {
            return handleLogout(exchange, chain);
        }

        // Injeta Authorization header se houver cookie de access token
        HttpCookie accessTokenCookie = exchange.getRequest().getCookies().getFirst("accessToken");
        if (accessTokenCookie != null) {
            String token = accessTokenCookie.getValue();
            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .build();
            exchange = exchange.mutate().request(mutatedRequest).build();
        }

        // Fluxo padrão: apenas login e refresh decoram a resposta
        if (method == HttpMethod.POST && path.matches(".*/auth/login$")) {
            return chain.filter(exchange.mutate()
                    .response(getResponseDecorator(exchange))
                    .build());
        }

        return chain.filter(exchange);
    }

    private Mono<Void> handleLogout(ServerWebExchange exchange, GatewayFilterChain chain) {
        HttpCookie accessTokenCookie = exchange.getRequest().getCookies().getFirst("accessToken");
        HttpCookie refreshTokenCookie = exchange.getRequest().getCookies().getFirst("refreshToken");

        String accessToken = accessTokenCookie != null ? accessTokenCookie.getValue() : "";
        String refreshToken = refreshTokenCookie != null ? refreshTokenCookie.getValue() : "";

        String form = "refresh_token=" + URLEncoder.encode(refreshToken, StandardCharsets.UTF_8);
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .build();

        mutatedRequest = getServerHttpRequest(exchange.mutate().request(mutatedRequest).build(), form);

        ServerHttpResponseDecorator decoratedResponse = getLogoutResponseDecorator(exchange);

        return chain.filter(exchange.mutate()
                .request(mutatedRequest)
                .response(decoratedResponse)
                .build());
    }

    private ServerHttpResponseDecorator getResponseDecorator(ServerWebExchange exchange) {
        ServerHttpResponse originalResponse = exchange.getResponse();
        return new ServerHttpResponseDecorator(originalResponse) {
            @Override
            @NonNull
            public Mono<Void> writeWith(@NonNull Publisher<? extends DataBuffer> body) {
                return DataBufferUtils.join(Flux.from(body))
                        .flatMap(buffer -> {
                            byte[] bytes = new byte[buffer.readableByteCount()];
                            buffer.read(bytes);
                            DataBufferUtils.release(buffer);

                            try {
                                JsonNode root = MAPPER.readTree(bytes);
                                String access = root.path("access_token").asText(null);
                                String refresh = root.path("refresh_token").asText(null);

                                if (access != null && refresh != null) {
                                    ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", refresh)
                                            .httpOnly(true)
                                            .secure(true)
                                            .path("/")
                                            .maxAge(7 * 24 * 3600)
                                            .sameSite("Lax")
                                            .build();
                                    getDelegate().getHeaders().add(HttpHeaders.SET_COOKIE, refreshCookie.toString());

                                    ResponseCookie accessCookie = ResponseCookie.from("accessToken", access)
                                            .httpOnly(true)
                                            .secure(true)
                                            .path("/")
                                            .maxAge(15 * 60)
                                            .sameSite("Lax")
                                            .build();
                                    getDelegate().getHeaders().add(HttpHeaders.SET_COOKIE, accessCookie.toString());

                                    // Extrai exp
                                    Long exp = extractExpFromToken(access);

                                    // Resposta simplificada
                                    String successResponse = String.format(
                                            "{\"message\":\"Login bem-sucedido\",\"exp\":%d}",
                                            exp != null ? exp : (System.currentTimeMillis() / 1000) + 900
                                    );

                                    byte[] successBytes = successResponse.getBytes(StandardCharsets.UTF_8);
                                    getDelegate().setStatusCode(HttpStatus.OK);
                                    getDelegate().getHeaders().setContentType(MediaType.APPLICATION_JSON);
                                    getDelegate().getHeaders().setContentLength(successBytes.length);

                                    return super.writeWith(Mono.just(getDelegate().bufferFactory().wrap(successBytes)));
                                }

                                // Caso não tenha tokens, mantém resposta original
                                getDelegate().getHeaders().setContentType(MediaType.APPLICATION_JSON);
                                return super.writeWith(Mono.just(getDelegate().bufferFactory().wrap(bytes)));

                            } catch (Exception e) {
                                // Em caso de erro, retorna original
                                return super.writeWith(Mono.just(getDelegate().bufferFactory().wrap(bytes)));
                            }
                        });
            }
        };
    }

    private static ServerHttpResponseDecorator getLogoutResponseDecorator(ServerWebExchange exchange) {
        ServerHttpResponse originalResponse = exchange.getResponse();
        return new ServerHttpResponseDecorator(originalResponse) {
            @Override
            @NonNull
            public Mono<Void> writeWith(@NonNull Publisher<? extends DataBuffer> body) {
                ResponseCookie expiredAccessCookie = ResponseCookie.from("accessToken", "")
                        .httpOnly(true)
                        .secure(true)
                        .path("/")
                        .maxAge(0)
                        .sameSite("Lax")
                        .build();

                ResponseCookie expiredRefreshCookie = ResponseCookie.from("refreshToken", "")
                        .httpOnly(true)
                        .secure(true)
                        .path("/")
                        .maxAge(0)
                        .sameSite("Lax")
                        .build();

                getDelegate().getHeaders().add(HttpHeaders.SET_COOKIE, expiredAccessCookie.toString());
                getDelegate().getHeaders().add(HttpHeaders.SET_COOKIE, expiredRefreshCookie.toString());
                getDelegate().setStatusCode(HttpStatus.NO_CONTENT);
                getDelegate().getHeaders().remove(HttpHeaders.CONTENT_LENGTH);

                return super.writeWith(Mono.empty());
            }
        };
    }

    private static ServerHttpRequest getServerHttpRequest(ServerWebExchange exchange, String form) {
        byte[] bytes = form.getBytes(StandardCharsets.UTF_8);
        return new ServerHttpRequestDecorator(exchange.getRequest()) {
            @Override
            @NonNull
            public Flux<DataBuffer> getBody() {
                DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
                return Flux.just(buffer);
            }

            @Override
            @NonNull
            public HttpHeaders getHeaders() {
                HttpHeaders headers = new HttpHeaders();
                headers.putAll(super.getHeaders());
                headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
                headers.setContentLength(bytes.length);
                return headers;
            }
        };
    }

    private Long extractExpFromToken(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) return null;

            byte[] payloadBytes = java.util.Base64.getUrlDecoder().decode(parts[1]);
            JsonNode payloadJson = MAPPER.readTree(new String(payloadBytes, StandardCharsets.UTF_8));
            return payloadJson.path("exp").asLong();
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 10;
    }
}
