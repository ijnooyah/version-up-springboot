package com.ijnooyah.study.springboot.config.auth;

import com.ijnooyah.study.springboot.config.auth.dto.OAuthAttributes;
import com.ijnooyah.study.springboot.config.auth.dto.SessionUser;
import com.ijnooyah.study.springboot.domain.user.User;
import com.ijnooyah.study.springboot.domain.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpSession;
import java.util.Collections;

@RequiredArgsConstructor
@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private final UserRepository userRepository;
    private final HttpSession httpSession;
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        // registrationId
        // 현재 로그인 진행 중인 서비스를 구분하는 코드
        // 지금은 구글만 사용하는 불필요한 값이지만, 이후 네이버 로그인 연동시에 네이버 로그인인지, 구글 로그인인지 구분하기 위해 사용한다.

        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails()
                .getUserInfoEndpoint().getUserNameAttributeName();
        // userNameAttributeName
        // OAuth2 로그인 진행시 키가 되는 필드값을 이야기함. Primary Key와 같은 의미
        // 구글의 경우 기본적으로 코드를 지원하지만, 네이버 카카오등은 기본 지원하지 않는다. 구글의 기본 코드는 "sub"이다.
        // 이후 네이버 로그인과 구글 로그인을 동시 지원할 때 사용된다.
        OAuthAttributes attributes = OAuthAttributes.of(registrationId, userNameAttributeName, oAuth2User.getAttributes());
        // OAuthAttributes
        // OAuth2UserService를 통해 가져온 OAuth2User의 attribute를 담을 클래스
        // 이후 네이버 등 다른 소셜 로그인도 이 클래스를 사용한다.

        User user = saveOrUpdate(attributes);

        httpSession.setAttribute("user", new SessionUser(user));
        // SessionUSer
        // 세션에 사용자 정보를 저장하기위한 Dto 클래스
        // 왜 User 클래스를 쓰지않고 새로 만들어 쓰는가??
        // User 클래스를 사용했다면 에러가 발생한다 (Failde to covert from type[java.lang.Object] to type [byte[]] for value~~)
        // 이는 세션에 저장하기 위해 User 클래스를 세션에 저장하려고 하니, User 클래스에 직렬화를 구현하지 않았다는 의미의 에러이다.
        // 오류를 해결하기위해 User 클래스에 직렬화 코드를 넣으면 되나?
        // 이건. 좀 그렇다 왜냐면 User 클래스는 엔티티이기때문이다. 엔티티 클래스에는 언제 다른 엔티티와 관계가 형성될지 모른다.
        // 예를들어 @OneToMany, @ManyToMany 등 자식 엔티티를 갖고있다면 직렬화 대상에 자식들까지 포함되니 성능 이슈, 부수효과가 발생할 확률이 높음
        // 그래서 직렬화 기능을 가진 세션 Dto를 하나 추가로 만드는 것이 이후 운영 및 유지보수 할 때 많은 도움이 된다.
        return new DefaultOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority(user.getRoleKey())),
                            attributes.getAttributes(),
                            attributes.getNameAttributeKey());
    }

    private User saveOrUpdate(OAuthAttributes attributes) {
        User user = userRepository.findByEmail(attributes.getEmail())
                .map(entity -> entity.update(attributes.getName(), attributes.getPicture()))
                .orElse(attributes.toEntity());
        // userRepository.findByEmail이 null이면 orElse의 인자가 리턴된다..

        return userRepository.save(user);
    }
}
