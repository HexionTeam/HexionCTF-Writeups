# Well Known - Solution

Created by Yarin ([GitHub](https://github.com/CmdEngineer) / [Twitter](https://twitter.com/CmdEngineer_))

## Description

Well... it's known (:

https://wk.hexionteam.com

## Solution

You start with nothing a 404 page. But some well known pages do exist.

### robots.txt

```html
Sitemap: sitemap.xml
Allow: *
```

### sitemap.xml

```xml
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
        <loc>https://wk.hexionteam.com/404.html</loc>
    </url>
    <url>
        <loc>https://wk.hexionteam.com/robots.txt</loc>
    </url>
    <url>
        <loc>https://wk.hexionteam.com/.well-known/security.txt</loc>
    </url>
</urlset>
```

### ./well-known/security.txt

```html
Flag: hexCTF{th4nk_y0u_liv3_0v3rfl0w}
```

Flag: `hexCTF{th4nk_y0u_liv3_0v3rfl0w}`
