"use client";

import * as React from "react";
import { motion, useAnimationFrame, useMotionValue } from "motion/react";
import { enrichTweet, type EnrichedTweet } from "react-tweet";

import type { Tweet } from "react-tweet/api";

import { cn } from "#lib/utils";

import type { TweetItem } from "./vertical-marquee.types";

interface TwitterIconProps {
  className?: string;
  [key: string]: unknown;
}

const Twitter = ({ className, ...props }: TwitterIconProps) => (
  <svg
    stroke="currentColor"
    fill="currentColor"
    strokeWidth="0"
    viewBox="0 0 24 24"
    height="1em"
    width="1em"
    xmlns="http://www.w3.org/2000/svg"
    className={className}
    {...props}
  >
    <g>
      <path fill="none" d="M0 0h24v24H0z" />
      <path d="M22.162 5.656a8.384 8.384 0 0 1-2.402.658A4.196 4.196 0 0 0 21.6 4c-.82.488-1.719.83-2.656 1.015a4.182 4.182 0 0 0-7.126 3.814 11.874 11.874 0 0 1-8.62-4.37 4.168 4.168 0 0 0-.566 2.103c0 1.45.738 2.731 1.86 3.481a4.168 4.168 0 0 1-1.894-.523v.052a4.185 4.185 0 0 0 3.355 4.101 4.21 4.21 0 0 1-1.89.072A4.185 4.185 0 0 0 7.97 16.65a8.394 8.394 0 0 1-6.191 1.732 11.83 11.83 0 0 0 6.41 1.88c7.693 0 11.9-6.373 11.9-11.9 0-.18-.005-.362-.013-.54a8.496 8.496 0 0 0 2.087-2.165z" />
    </g>
  </svg>
);

const Verified = ({ className, ...props }: TwitterIconProps) => (
  <svg
    aria-label="Verified Account"
    viewBox="0 0 24 24"
    className={className}
    {...props}
  >
    <g fill="currentColor">
      <path d="M22.5 12.5c0-1.58-.875-2.95-2.148-3.6.154-.435.238-.905.238-1.4 0-2.21-1.71-3.998-3.818-3.998-.47 0-.92.084-1.336.25C14.818 2.415 13.51 1.5 12 1.5s-2.816.917-3.437 2.25c-.415-.165-.866-.25-1.336-.25-2.11 0-3.818 1.79-3.818 4 0 .494.083.964.237 1.4-1.272.65-2.147 2.018-2.147 3.6 0 1.495.782 2.798 1.942 3.486-.02.17-.032.34-.032.514 0 2.21 1.708 4 3.818 4 .47 0 .92-.086 1.335-.25.62 1.334 1.926 2.25 3.437 2.25 1.512 0 2.818-.916 3.437-2.25.415.163.865.248 1.336.248 2.11 0 3.818-1.79 3.818-4 0-.174-.012-.344-.033-.513 1.158-.687 1.943-1.99 1.943-3.484zm-6.616-3.334l-4.334 6.5c-.145.217-.382.334-.625.334-.143 0-.288-.04-.416-.126l-.115-.094-2.415-2.415c-.293-.293-.293-.768 0-1.06s.768-.294 1.06 0l1.77 1.767 3.825-5.74c.23-.345.696-.436 1.04-.207.346.23.44.696.21 1.04z" />
    </g>
  </svg>
);

export const truncate = (str: string | null, length: number) => {
  if (!str || str.length <= length) return str;
  return `${str.slice(0, length - 3)}...`;
};

const Skeleton = ({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) => {
  return (
    <div className={cn("rounded-md bg-primary/10", className)} {...props} />
  );
};

export const TweetSkeleton = ({
  className,
  ...props
}: {
  className?: string;
  [key: string]: unknown;
}) => (
  <div
    className={cn(
      "flex size-full max-h-max min-w-72 flex-col gap-3 rounded-[28px] border border-border/60 bg-background/90 p-4 backdrop-blur-sm",
      className,
    )}
    {...props}
  >
    <div className="flex flex-row gap-3">
      <Skeleton className="size-11 shrink-0 rounded-full" />
      <Skeleton className="h-11 w-full" />
    </div>
    <Skeleton className="h-24 w-full" />
    <Skeleton className="h-44 w-full rounded-2xl" />
  </div>
);

export const TweetNotFound = ({
  className,
  ...props
}: {
  className?: string;
  [key: string]: unknown;
}) => (
  <div
    className={cn(
      "flex min-h-56 size-full flex-col items-center justify-center gap-2 rounded-[28px] border border-dashed border-border/70 bg-muted/40 p-6 text-center",
      className,
    )}
    {...props}
  >
    <h3 className="text-base font-medium">Tweet not found</h3>
    <p className="text-muted-foreground text-sm">
      This post could not be loaded.
    </p>
  </div>
);

export const TweetHeader = ({ tweet }: { tweet: EnrichedTweet }) => (
  <div className="flex flex-row items-start justify-between tracking-normal">
    <div className="flex items-center space-x-3">
      <a
        href={tweet.user.url}
        target="_blank"
        rel="noreferrer"
        className="shrink-0"
      >
        <img
          title={`Profile picture of ${tweet.user.name}`}
          alt={tweet.user.screen_name}
          height={48}
          width={48}
          src={tweet.user.profile_image_url_https}
          className="overflow-hidden rounded-full"
        />
      </a>
      <div className="flex flex-col gap-0.5">
        <a
          href={tweet.user.url}
          target="_blank"
          rel="noreferrer"
          className="text-foreground flex items-center font-medium whitespace-nowrap transition-opacity hover:opacity-80"
        >
          {truncate(tweet.user.name, 20)}
          {(tweet.user.verified || tweet.user.is_blue_verified) && (
            <Verified className="ml-1 inline size-4 text-sky-500" />
          )}
        </a>
        <div className="flex items-center space-x-1">
          <a
            href={tweet.user.url}
            target="_blank"
            rel="noreferrer"
            className="text-muted-foreground hover:text-foreground text-sm transition-colors"
          >
            @{truncate(tweet.user.screen_name, 16)}
          </a>
        </div>
      </div>
    </div>
    <a href={tweet.url} target="_blank" rel="noreferrer">
      <span className="sr-only">Link to tweet</span>
      <Twitter className="text-muted-foreground hover:text-foreground size-5 transition-transform hover:scale-105" />
    </a>
  </div>
);

export const TweetBody = ({ tweet }: { tweet: EnrichedTweet }) => (
  <div className="whitespace-pre-wrap break-words text-[15px] leading-relaxed tracking-normal">
    {tweet.entities.map((entity, idx) => {
      switch (entity.type) {
        case "url":
        case "symbol":
        case "hashtag":
        case "mention":
          return (
            <a
              key={idx}
              href={entity.href}
              target="_blank"
              rel="noopener noreferrer"
              className="text-muted-foreground hover:text-foreground text-[15px] font-normal transition-colors"
            >
              <span>{entity.text}</span>
            </a>
          );
        case "text":
          return (
            <span
              key={idx}
              className="text-foreground text-[15px] font-normal"
              dangerouslySetInnerHTML={{ __html: entity.text }}
            />
          );
        default:
          return null;
      }
    })}
  </div>
);

function getCardThumbnail(tweet: unknown) {
  const card = tweet as {
    card?: {
      binding_values?: {
        thumbnail_image_large?: {
          image_value?: {
            url?: string;
          };
        };
      };
    };
  };

  return card.card?.binding_values?.thumbnail_image_large?.image_value?.url;
}

function getBestVideoSource(tweet: EnrichedTweet) {
  const variants = tweet.video?.variants ?? [];
  const mp4Variants = variants.filter((variant) =>
    variant.src.includes(".mp4"),
  );

  return (
    mp4Variants.at(-1)?.src ?? variants.find((variant) => variant.src)?.src
  );
}

function normalizeTweet(tweet: Tweet): Tweet {
  return {
    ...tweet,
    display_text_range: [...tweet.display_text_range],
    entities: {
      hashtags: tweet.entities.hashtags ?? [],
      urls: tweet.entities.urls ?? [],
      user_mentions: tweet.entities.user_mentions ?? [],
      symbols: tweet.entities.symbols ?? [],
      media: tweet.entities.media,
    },
    quoted_tweet: tweet.quoted_tweet
      ? normalizeQuotedTweet(tweet.quoted_tweet)
      : undefined,
  };
}

function normalizeQuotedTweet(
  tweet: NonNullable<Tweet["quoted_tweet"]>,
): NonNullable<Tweet["quoted_tweet"]> {
  return {
    ...tweet,
    display_text_range: [...tweet.display_text_range],
    entities: {
      hashtags: tweet.entities.hashtags ?? [],
      urls: tweet.entities.urls ?? [],
      user_mentions: tweet.entities.user_mentions ?? [],
      symbols: tweet.entities.symbols ?? [],
      media: tweet.entities.media,
    },
  };
}

export const TweetMedia = ({ tweet }: { tweet: EnrichedTweet }) => {
  const thumbnail = getCardThumbnail(tweet);
  const videoSource = getBestVideoSource(tweet);

  if (!tweet.video && !tweet.photos?.length && !thumbnail) {
    return null;
  }

  return (
    <div className="flex flex-1 items-center justify-center">
      {tweet.video ? (
        <video
          poster={tweet.video.poster}
          autoPlay
          loop
          muted
          playsInline
          className="w-full rounded-2xl border border-border/60"
        >
          {videoSource ? <source src={videoSource} type="video/mp4" /> : null}
          Your browser does not support the video tag.
        </video>
      ) : tweet.photos?.length ? (
        <div className="relative flex w-full snap-x snap-mandatory gap-3 overflow-x-auto pb-1">
          {tweet.photos.map((photo) => (
            <img
              key={photo.url}
              src={photo.url}
              width={photo.width}
              height={photo.height}
              title={`Photo by ${tweet.user.name}`}
              alt={tweet.text}
              className="h-64 w-[88%] shrink-0 snap-center rounded-2xl border border-border/60 object-cover"
            />
          ))}
        </div>
      ) : (
        <img
          src={thumbnail}
          className="h-64 w-full rounded-2xl border border-border/60 object-cover"
          alt={tweet.text}
        />
      )}
    </div>
  );
};

export const MagicTweet = ({
  tweet,
  className,
  ...props
}: {
  tweet: Tweet;
  className?: string;
}) => {
  const enrichedTweet = enrichTweet(normalizeTweet(tweet));

  return (
    <article
      className={cn(
        "relative flex h-fit w-full flex-col gap-4 overflow-hidden rounded-[28px] border border-border/60 bg-background/95 p-5 backdrop-blur-sm",
        className,
      )}
      {...props}
    >
      <TweetHeader tweet={enrichedTweet} />
      <TweetBody tweet={enrichedTweet} />
      <TweetMedia tweet={enrichedTweet} />
    </article>
  );
};

interface ColumnProps {
  tweets: TweetItem[];
  speed: number;
  gap: number;
  reverse?: boolean;
  paused: boolean;
  tweetClassName?: string;
}

function MarqueeColumn({
  tweets,
  speed,
  gap,
  reverse = false,
  paused,
  tweetClassName,
}: ColumnProps) {
  const wrapRef = React.useRef<HTMLDivElement>(null);
  const [singleHeight, setSingleHeight] = React.useState(0);
  const y = useMotionValue(0);
  const pos = React.useRef(0);
  const currentSpeed = React.useRef(0);
  const initialized = React.useRef(false);

  React.useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;

    const measure = () => {
      const height = el.scrollHeight / 2;
      if (height <= 0) return;
      setSingleHeight(height);
      if (!initialized.current) {
        pos.current = reverse ? -height : 0;
        y.set(pos.current);
        initialized.current = true;
      }
    };

    const observer = new ResizeObserver(measure);
    observer.observe(el);
    measure();

    return () => observer.disconnect();
  }, [reverse, tweets, y]);

  useAnimationFrame((_, delta) => {
    if (!singleHeight) return;

    const targetSpeed = paused ? 0 : singleHeight / speed;
    currentSpeed.current += (targetSpeed - currentSpeed.current) * 0.08;

    const step = currentSpeed.current * (delta / 1000);
    if (reverse) {
      pos.current += step;
      if (pos.current >= 0) pos.current -= singleHeight;
    } else {
      pos.current -= step;
      if (pos.current <= -singleHeight) pos.current += singleHeight;
    }

    y.set(pos.current);
  });

  const doubled = [...tweets, ...tweets];

  return (
    <div className="min-w-0 flex-1 overflow-hidden">
      <motion.div ref={wrapRef} style={{ y }}>
        {doubled.map((item, index) => (
          <div
            key={`${item.id}-${index}`}
            style={{ marginBottom: `${gap}px` }}
            className="w-full"
          >
            {item.tweet ? (
              <MagicTweet tweet={item.tweet} className={tweetClassName} />
            ) : (
              <TweetNotFound className={tweetClassName} />
            )}
          </div>
        ))}
      </motion.div>
    </div>
  );
}

export function VerticalMarqueeClient({
  tweets,
  columns = 2,
  speed = 20,
  gap = 16,
  blurSize = 120,
  pauseOnHover = true,
  className,
  tweetClassName,
}: {
  tweets: TweetItem[];
  columns?: 1 | 2;
  speed?: number;
  gap?: number;
  blurSize?: number;
  pauseOnHover?: boolean;
  className?: string;
  tweetClassName?: string;
}) {
  const [paused, setPaused] = React.useState(false);

  const mid = Math.ceil(tweets.length / 2);
  const col1 = columns === 2 ? tweets.slice(0, mid) : tweets;
  const col2 = columns === 2 ? tweets.slice(mid) : tweets;

  const mask = `linear-gradient(to bottom, transparent 0%, black ${blurSize}px, black calc(100% - ${blurSize}px), transparent 100%)`;

  return (
    <div
      className={cn("h-full w-full overflow-hidden", className)}
      style={{ maskImage: mask, WebkitMaskImage: mask }}
      onMouseEnter={() => pauseOnHover && setPaused(true)}
      onMouseLeave={() => setPaused(false)}
    >
      <div className="flex h-full" style={{ gap: `${gap}px` }}>
        <MarqueeColumn
          tweets={col1.length ? col1 : tweets}
          speed={speed}
          gap={gap}
          paused={paused}
          tweetClassName={tweetClassName}
        />
        {columns === 2 && (
          <MarqueeColumn
            tweets={col2.length ? col2 : tweets}
            speed={speed * 1.25}
            gap={gap}
            reverse
            paused={paused}
            tweetClassName={tweetClassName}
          />
        )}
      </div>
    </div>
  );
}
