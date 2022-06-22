package com.ijnooyah.study.springboot.web.dto;

import com.ijnooyah.study.springboot.domain.posts.Posts;
import lombok.Getter;

@Getter
public class PostsResponseDto {
    // PostsResponseDto는 Entity의 필드 중 일부만 사용하므로 생성자로 Entity를 받아 필드에 값을 넣는다.
    // 굳이 모든 필드를 가진 생성자가 필요하진 않음.

    private Long id;
    private String title;
    private String content;
    private String author;

    public PostsResponseDto(Posts entity) {
        this.id = entity.getId();
        this.title = entity.getTitle();
        this.content = entity.getContent();
        this.author = entity.getAuthor();

    }
}
